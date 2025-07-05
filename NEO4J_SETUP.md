Neo4j Setup Guide
This document provides instructions for setting up a local Neo4j graph database instance using Docker. This is the recommended setup for all developers working on Phase 2 of the AI-Powered Migration Assessment Tool.

Prerequisites
Docker Desktop installed and running on your local machine.

1. Running Neo4j with Docker
We will use the official Neo4j Docker image. This command will start a Neo4j container, expose the necessary ports, and set a default password.

Open your terminal and run the following command:

docker run \
    --name neo4j-assessment-db \
    -p 7474:7474 \
    -p 7687:7687 \
    -d \
    -e NEO4J_AUTH=neo4j/password123
    neo4j:5.20.0

Explanation of the command:

--name neo4j-assessment-db: Assigns a memorable name to our container.

-p 7474:7474: Maps the Neo4j Browser port to your local machine.

-p 7687:7687: Maps the Bolt protocol port (which our Python driver will use) to your local machine.

-d: Runs the container in detached mode (in the background).

-e NEO4J_AUTH=neo4j/password123: Sets the username to neo4j and the password to password123. You can change the password, but remember what you set it to.

neo4j:5.20.0: Specifies the official Neo4j image and version to use.

2. Accessing the Neo4j Browser
Once the container is running, you can access the Neo4j Browser to visually interact with the database.

Open your web browser and navigate to: http://localhost:7474

You will be prompted to log in. Use the credentials you set in the Docker command:

Username: neo4j

Password: password123

You are now connected to your local Neo4j instance.

3. Connection Details for the Application
Our Python application will connect to this Neo4j instance using environment variables. You will need to set these in your local development environment (e.g., in your shell profile or a .env file).

NEO4J_URI: The Bolt URI for the database.

bolt://localhost:7687

NEO4J_USER: The username.

neo4j

NEO4J_PASS: The password you set.

password123

4. Stopping and Starting the Container
To stop the container:

docker stop neo4j-assessment-db

To start the container again later:

docker start neo4j-assessment-db
