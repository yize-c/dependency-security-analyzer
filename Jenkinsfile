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
        stage('Deploy') {
            environment {
                AWS_ACCESS_KEY_ID     = credentials('aws-access-key-id')
                AWS_SECRET_ACCESS_KEY = credentials('aws-secret-access-key')
                AWS_DEFAULT_REGION    = 'us-west-2'
            }
            steps {
                sh 'docker run --rm dep-analyzer --file examples/vulnerable-requirements.txt --output json > report.json'
                sh 'aws s3 cp report.json s3://dep-analyzer-reports-yizec-2026/report-${BUILD_NUMBER}.json'
            }
        }
    }
}