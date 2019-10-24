FROM python:3

# Create a working app directory
WORKDIR /shcheck

# Install app dependencies
RUN pip install request
RUN pip install parse

# Run the python file
CMD [ "python", "shcheck.py"]

