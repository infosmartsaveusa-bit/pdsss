# Use the official Playwright Python image
# This image includes Python, Playwright, and the necessary browser binaries/dependencies
FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

# Set the working directory inside the container
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies required for OpenCV and Pyzbar
RUN apt-get update && apt-get install -y \
    libgl1 \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file explicitly
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (specifically Chromium for scanning)
# Although the base image has them, this ensures compatibility with the installed pip package
RUN playwright install chromium

# Copy the rest of the application code
COPY . .

# Expose the port
EXPOSE 8000

# Start the application
# We use shell form to allow variable expansion for $PORT provided by Render/Railway
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
