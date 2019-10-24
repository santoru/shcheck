FROM python:3.7-alpine3.10

# Copy current directory
COPY . /shcheck

# Create working directory
WORKDIR /shcheck

# Run command
ENTRYPOINT ["python",  "shcheck.py"]