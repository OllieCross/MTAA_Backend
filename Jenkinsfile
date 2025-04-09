pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "flask_api"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build') {
            steps {
                script {
                    sh 'docker compose stop flask_api || true'
                    sh 'docker compose rm -f flask_api || true'
                    sh 'docker compose up --build -d flask_api'
                }
            }
        }
        stage('Test') {
            steps {
                sh 'echo "Running tests..."'
            }
        }
        stage('Deploy') {
            steps {
                script {
                    sh '''
                        docker stop flask_api || true
                        docker rm flask_api || true
                        docker run -d --name flask_api -p 5001:5001 ${DOCKER_IMAGE}:latest
                    '''
                }
            }
        }
    }
    post {
        failure {
            echo 'Pipeline failed! Check logs for details.'
        }
    }
}
