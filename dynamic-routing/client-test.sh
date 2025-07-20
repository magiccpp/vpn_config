if [ $# -lt 2 ]; then
  echo "Usage: ./client.sh test_ip port"
  exit -1
fi

curl -X POST http://127.0.0.1:8080/test_route \
     -H "Content-Type: application/json" \
     -d "{
           \"destination_ip\": \"$1\",
           \"destination_port\": \"$2\",
           \"current_gateway\": \"10.8.0.1\",
           \"alternative_gateways\": [\"192.168.71.1\"]
         }"

