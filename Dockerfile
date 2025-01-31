# Step 1: Use a Python base image
FROM python:3.9-slim
# Step 2: Set the working directory in the container
WORKDIR /app
# Step 3: Copy the Python script and any additional necessary files to the container
COPY script.py /app/
# Step 4: Install dependencies
RUN pip install --no-cache-dir cryptography pwinput
# Step 6: Define the default command to run the script
ENTRYPOINT ["python", "script.py"]
