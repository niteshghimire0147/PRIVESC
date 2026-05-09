FROM python:3.11-slim

LABEL maintainer="ghimirenitesh8@gmail.com"
LABEL description="Linux Privilege Escalation Automation Toolkit — detection-only scanner"
LABEL version="2.1.0"

WORKDIR /app

# Copy all project files
COPY . .

# Install as a package (no external deps needed)
RUN pip install --no-cache-dir -e .

# Create output directory
RUN mkdir -p /app/output

# Default: show help. Override with: docker run ... --format html -v
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
