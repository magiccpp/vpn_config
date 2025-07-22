import asyncio
from aiohttp import web
import json
import subprocess
import time
from typing import List, Dict, Any, Optional

# Define a global lock to prevent concurrent route modifications
route_lock = asyncio.Lock()

async def execute_command(cmd: List[str]) -> Dict[str, Any]:
    """
    Execute a shell command asynchronously and return the result.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return {
            "returncode": process.returncode,
            "stdout": stdout.decode().strip(),
            "stderr": stderr.decode().strip()
        }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e)
        }

async def add_route(destination: str, gateway: str) -> Dict[str, Any]:
    """
    Add a route to the destination via the specified gateway.
    """
    cmd = ["ip", "route", "add", destination, "via", gateway]
    return await execute_command(cmd)

async def del_route(destination: str) -> Dict[str, Any]:
    """
    Delete the route to the specified destination.
    """
    cmd = ["ip", "route", "del", destination]
    return await execute_command(cmd)

async def measure_tcp_rtt(dest_ip: str, dest_port: int, timeout: float = 2.0) -> Optional[float]:
    """
    Measure the TCP RTT by attempting to establish a connection.
    For port 443, ensure that data is transferred by performing an SSL handshake
    and sending an HTTP HEAD request.
    
    Returns RTT in milliseconds or None if failed.
    """
    start_time = time.time()
    reader = writer = None
    try:
        if dest_port == 443:
            # Create an SSL context
            ssl_context = ssl.create_default_context()
            
            # Initiate the SSL connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(dest_ip, dest_port, ssl=ssl_context),
                timeout=timeout
            )
            
            # Send a simple HTTP HEAD request
            http_request = f"HEAD / HTTP/1.0\r\nHost: {dest_ip}\r\n\r\n"
            writer.write(http_request.encode('utf-8'))
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            
            # Wait for the response
            response = await asyncio.wait_for(reader.readline(), timeout=timeout)
            
            if not response:
                # No data received
                raise ConnectionError("No data received after sending HTTP HEAD request.")
            
        else:
            # For other ports, just establish a TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(dest_ip, dest_port),
                timeout=timeout
            )
        
        end_time = time.time()
        rtt = (end_time - start_time) * 1000  # Convert to milliseconds
        return rtt

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError, ConnectionError) as e:
        print(f"Error measuring RTT to {dest_ip}:{dest_port} - {e}")
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

async def test_gateway(destination: str, port: int, gateway: str, num_tests: int = 5) -> Dict[str, Any]:
    """
    Add route via gateway, perform multiple RTT measurements, and clean up.
    """
    result = {
        "gateway": gateway,
        "rtt_stats_ms": {
            "average": None,
            "minimum": None,
            "maximum": None,
            "individual_tests": []
        },
        "errors": []
    }
    try:
        # Add route
        add_res = await add_route(destination, gateway)
        if add_res["returncode"] != 0:
            result["errors"].append(f"Failed to add route: {add_res['stderr']}")
            return result

        # Wait for route to take effect
        await asyncio.sleep(1)

        # Perform multiple RTT measurements sequentially
        rtts = []
        for i in range(1, num_tests + 1):
            rtt = await measure_tcp_rtt(destination, port)
            if rtt is not None:
                rtts.append(rtt)
                result["rtt_stats_ms"]["individual_tests"].append({
                    "test_number": i,
                    "rtt_ms": rtt
                })
            else:
                result["rtt_stats_ms"]["individual_tests"].append({
                    "test_number": i,
                    "rtt_ms": None,
                    "error": "RTT measurement failed or timed out."
                })

        # Aggregate RTT results if any successful measurements exist
        successful_rtts = [rtt for rtt in rtts if rtt is not None]
        if successful_rtts:
            result["rtt_stats_ms"]["average"] = sum(successful_rtts) / len(successful_rtts)
            result["rtt_stats_ms"]["minimum"] = min(successful_rtts)
            result["rtt_stats_ms"]["maximum"] = max(successful_rtts)
        else:
            result["errors"].append("All RTT measurements failed or timed out.")

    except Exception as e:
        result["errors"].append(str(e))
    finally:
        # Remove the added route
        del_res = await del_route(destination)
        if del_res["returncode"] != 0:
            # Log the error; in a real application, consider proper logging
            result["errors"].append(f"Failed to delete route: {del_res['stderr']}")

    return result

async def handle_test_route(request: web.Request) -> web.Response:
    """
    Handle the POST request to test routes.
    Expects JSON with keys:
    - destination_ip: str
    - destination_port: int
    - current_gateway: str
    - alternative_gateways: List[str]
    - num_tests_per_gateway: Optional[int] (default: 5)
    """
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON payload."}, status=400)

    # Validate input
    required_fields = ["destination_ip", "destination_port", "current_gateway", "alternative_gateways"]
    for field in required_fields:
        if field not in data:
            return web.json_response({"error": f"Missing field: {field}"}, status=400)

    destination_ip = data["destination_ip"]
    destination_port = data["destination_port"]
    current_gateway = data["current_gateway"]
    alternative_gateways = data["alternative_gateways"]
    num_tests = data.get("num_tests_per_gateway", 5)  # Default to 5 tests

    if not isinstance(alternative_gateways, list):
        return web.json_response({"error": "alternative_gateways must be a list."}, status=400)

    if not isinstance(num_tests, int) or num_tests <= 0:
        return web.json_response({"error": "num_tests_per_gateway must be a positive integer."}, status=400)

    # Acquire the route lock to prevent concurrent modifications
    async with route_lock:
        results = []

        # Step 1: Remove existing route if it exists
        del_res = await del_route(destination_ip)
        if del_res["returncode"] != 0 and "No such process" not in del_res["stderr"] and "No such file" not in del_res["stderr"]:
            # "No such process" or "No route" is expected if the route doesn't exist
            results.append({
                "gateway": None,
                "rtt_stats_ms": None,
                "errors": [f"Failed to delete existing route: {del_res['stderr']}"]
            })

        # Function to process a single gateway
        async def process_gateway(gateway: str) -> Dict[str, Any]:
            return await test_gateway(destination_ip, destination_port, gateway, num_tests=num_tests)

        # Step 2-5: Test current gateway
        current_result = await process_gateway(current_gateway)
        results.append(current_result)

        # Step 6: Test alternative gateways concurrently with timeout
        tasks = []
        for alt_gw in alternative_gateways:
            task = asyncio.create_task(process_gateway(alt_gw))
            tasks.append(task)

        # Define a total timeout for all gateways
        overall_timeout = 30  # seconds
        try:
            alternative_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=overall_timeout
            )
            # Handle results and any exceptions
            for idx, res in enumerate(alternative_results):
                if isinstance(res, Exception):
                    results.append({
                        "gateway": alternative_gateways[idx],
                        "rtt_stats_ms": None,
                        "errors": [str(res)]
                    })
                else:
                    results.append(res)
        except asyncio.TimeoutError:
            # Handle gateways that did not respond in time
            for task_num, task in enumerate(tasks, 1):
                if not task.done():
                    task.cancel()
                    results.append({
                        "gateway": alternative_gateways[task_num - 1],
                        "rtt_stats_ms": None,
                        "errors": ["Operation timed out."]
                    })

        return web.json_response({"results": results})

async def init_app() -> web.Application:
    app = web.Application()
    app.router.add_post('/test_route', handle_test_route)
    return app

def main():
    app = asyncio.run(init_app())
    web.run_app(app, host='0.0.0.0', port=8080)

if __name__ == "__main__":
    main()


