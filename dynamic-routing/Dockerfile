# Use an official lightweight Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1   
ENV PYTHONUNBUFFERED=1          

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \             
    libpq-dev \                   
    libpcap-dev \                 
    lsof \                         
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for better security
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Set the working directory
WORKDIR /app

# Copy only the requirements to leverage Docker cache
# (Optional but recommended if you have a requirements.txt)
COPY requirements.txt /app/

# Install Python dependencies
# If you have a requirements.txt, uncomment the above COPY line and use the line below
# RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# If not using requirements.txt, install dependencies directly
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY dynamic-routing-client.py /app/
COPY config.json.docker /app/config.json
# (Optional) If you have other directories like configs or scripts, copy them as needed
# COPY config.json /app/config.json

# Expose Prometheus metrics port
EXPOSE 8100

# Define the default command to run your script with arguments
# Replace 'your_script.py' with the actual filename if different
# It's assumed that the config file will be mounted or provided at runtime
ENTRYPOINT ["python", "dynamic-routing-client.py"]

# Default arguments (can be overridden at runtime)
# Example: --config /app/config.json
CMD ["--config", "/app/config.json"]