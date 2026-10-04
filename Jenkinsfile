pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh 'python3 -m venv venv'
                sh '. venv/bin/activate && pip install -r requirements-dev.txt && pytest'
            }
        }
        stage('Build') {
            steps {
                sh 'docker build -t dep-analyzer .'
            }
        }
    }
}