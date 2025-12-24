# Kubernetes Authorization Audit with Slack Notifications
# Makefile for easy project management

# Load configuration from config.yaml if available, otherwise use env vars
DOCKER_USERNAME ?= $(shell if [ -f config.yaml ]; then grep -A 1 "^docker:" config.yaml | grep username | cut -d'"' -f2 | cut -d'"' -f1 || echo ""; fi)
SLACK_TOKEN ?= $(shell if [ -f config.yaml ]; then grep -A 1 "^slack:" config.yaml | grep bot_token | cut -d'"' -f2 | cut -d'"' -f1 || echo ""; fi)
OPENAI_API_KEY ?= $(shell if [ -f config.yaml ]; then grep -A 1 "^openai:" config.yaml | grep api_key | cut -d'"' -f2 | cut -d'"' -f1 || echo ""; fi)

IMAGE_NAME = kube-auth-manager
IMAGE_TAG ?= latest
FULL_IMAGE_NAME = $(DOCKER_USERNAME)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: help build deploy deploy-cron clean test users-create users-clean logs status helm-deploy helm-deploy-cron helm-clean helm-status setup-minikube check-minikube start-minikube stop-minikube reset-minikube docker-build docker-push docker-login config install activate secret openai-secret

# Default target
help:
	@echo "🔐 Kubernetes Authorization Audit with Slack Notifications"
	@echo ""
	@echo "Available targets:"
	@echo "  setup-minikube - Install and setup minikube (if needed)"
	@echo "  start-minikube - Start minikube cluster"
	@echo "  stop-minikube  - Stop minikube cluster"
	@echo "  reset-minikube - Delete and recreate minikube cluster"
	@echo "  check-minikube - Check minikube status"
	@echo "  docker-login   - Login to Docker Hub"
	@echo "  docker-build   - Build and push Docker image to Docker Hub"
	@echo "  build          - Build Docker image (for local use)"
	@echo "  deploy         - Deploy one-time job using kubectl/kustomize"
	@echo "  deploy-cron    - Deploy CronJob using kubectl/kustomize"
	@echo "  helm-deploy    - Deploy one-time job using Helm (recommended)"
	@echo "  helm-deploy-cron - Deploy CronJob using Helm"
	@echo "  clean          - Clean up all resources (kubectl)"
	@echo "  helm-clean     - Clean up Helm release"
	@echo "  config         - Create config.yaml from example"
	@echo "  install        - Install Python dependencies in virtual environment"
	@echo "  test           - Test Slack connection locally [uses config.yaml]"
	@echo "  users-create   - Create test users and service accounts (no Slack, no cleanup)"
	@echo "  users-clean    - Clean up test users and service accounts"
	@echo "  logs           - View application logs"
	@echo "  status         - Check deployment status"
	@echo "  helm-status    - Check Helm release status"
	@echo "  secret         - Create Kubernetes secret (requires SLACK_TOKEN)"
	@echo "  openai-secret  - Create OpenAI API key secret (requires OPENAI_API_KEY)"
	@echo ""
	@echo "Quick Start (Docker Hub):"
	@echo "  1. make config  # Create config.yaml from example"
	@echo "  2. Edit config.yaml with your secrets"
	@echo "  3. make docker-login DOCKER_USERNAME=your-username"
	@echo "  4. make docker-build DOCKER_USERNAME=your-username"
	@echo "  5. make setup-minikube"
	@echo "  6. make helm-deploy # Uses config.yaml values"
	@echo ""
	@echo "Note: config.yaml contains all secrets and is NOT committed to git"

# Check if minikube is installed
check-minikube:
	@echo "🔍 Checking minikube installation..."
	@if command -v minikube >/dev/null 2>&1; then \
		echo "✅ Minikube is installed"; \
		minikube version; \
	else \
		echo "❌ Minikube is not installed"; \
		echo "Run 'make setup-minikube' to install it"; \
		exit 1; \
	fi

# Install minikube
setup-minikube:
	@echo "🔧 Setting up minikube..."
	@if command -v minikube >/dev/null 2>&1; then \
		echo "✅ Minikube is already installed"; \
		minikube version; \
	else \
		echo "📦 Installing minikube..."; \
		if [ "$$(uname)" = "Darwin" ]; then \
			if command -v brew >/dev/null 2>&1; then \
				brew install minikube; \
			else \
				echo "❌ Homebrew not found"; \
				exit 1; \
			fi; \
		elif [ "$$(uname)" = "Linux" ]; then \
			curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64; \
			sudo install minikube-linux-amd64 /usr/local/bin/minikube; \
			rm minikube-linux-amd64; \
		fi; \
	fi
	@$(MAKE) start-minikube

# Start minikube cluster
start-minikube:
	@echo "🚀 Starting minikube cluster..."
	@if ! command -v minikube >/dev/null 2>&1; then \
		echo "❌ Minikube not found. Run 'make setup-minikube' first"; \
		exit 1; \
	fi
	@if minikube status 2>&1 | grep -q "host: Running"; then \
		echo "✅ Minikube is already running"; \
		echo "ℹ️  To restart, run 'make reset-minikube' first"; \
	else \
		minikube delete 2>/dev/null || true; \
		minikube start --driver=docker --cpus=2 --memory=3072; \
	fi
	@echo "✅ Minikube is running!"

# Stop minikube cluster
stop-minikube:
	@echo "🛑 Stopping minikube cluster..."
	@minikube stop
	@echo "✅ Minikube stopped!"

# Reset minikube cluster
reset-minikube:
	@echo "🔄 Resetting minikube cluster..."
	@minikube delete
	@$(MAKE) start-minikube

# Login to Docker Hub
docker-login:
	@echo "🔐 Logging in to Docker Hub..."
	@if [ -z "$(DOCKER_USERNAME)" ]; then \
		echo "❌ DOCKER_USERNAME is required"; \
		echo "Usage: make docker-login DOCKER_USERNAME=your-username"; \
		exit 1; \
	fi
	@docker login
	@echo "✅ Logged in to Docker Hub!"

# Build Docker image
build:
	@echo "🔨 Building Docker image..."
	@cd src && docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "✅ Docker image built: $(IMAGE_NAME):$(IMAGE_TAG)"

# Build and push Docker image
docker-build: docker-login build
	@echo "📤 Pushing Docker image to Docker Hub..."
	@if [ -z "$(DOCKER_USERNAME)" ]; then \
		echo "❌ DOCKER_USERNAME is required"; \
		exit 1; \
	fi
	@docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(FULL_IMAGE_NAME)
	@docker push $(FULL_IMAGE_NAME)
	@echo "✅ Docker image pushed: $(FULL_IMAGE_NAME)"

# Deploy using kubectl/kustomize
deploy: check-minikube
	@if [ -z "$(SLACK_TOKEN)" ]; then \
		echo "❌ SLACK_TOKEN not found in config.yaml or environment"; \
		exit 1; \
	fi
	@$(MAKE) secret
	@kubectl apply -k k8s/
	@echo "✅ Deployment complete!"

# Deploy CronJob using kubectl/kustomize
deploy-cron: check-minikube
	@if [ -z "$(SLACK_TOKEN)" ]; then \
		echo "❌ SLACK_TOKEN not found in config.yaml or environment"; \
		exit 1; \
	fi
	@$(MAKE) secret
	@kubectl apply -f k8s/kube-auth-cronjob.yaml
	@echo "✅ CronJob deployment complete!"

# Deploy using Helm
helm-deploy: check-minikube
	@if [ -z "$(SLACK_TOKEN)" ]; then \
		echo "❌ SLACK_TOKEN not found in config.yaml or environment"; \
		exit 1; \
	fi
	@kubectl create namespace kube-auth --dry-run=client -o yaml | kubectl apply -f -
	@if [ -n "$(DOCKER_USERNAME)" ]; then \
		helm upgrade --install kube-auth-manager ./helm/kube-auth-manager \
			--set slack.token="$(SLACK_TOKEN)" \
			--set openai.apiKey="$(OPENAI_API_KEY)" \
			--set image.repository="$(DOCKER_USERNAME)/$(IMAGE_NAME)" \
			--set image.tag="$(IMAGE_TAG)" \
			--set image.pullPolicy="Always" \
			--namespace kube-auth \
			--wait; \
	else \
		$(MAKE) build; \
		helm upgrade --install kube-auth-manager ./helm/kube-auth-manager \
			--set slack.token="$(SLACK_TOKEN)" \
			--set openai.apiKey="$(OPENAI_API_KEY)" \
			--namespace kube-auth \
			--wait; \
	fi
	@echo "✅ Helm deployment complete!"

# Deploy CronJob using Helm
helm-deploy-cron: check-minikube
	@if [ -z "$(SLACK_TOKEN)" ]; then \
		echo "❌ SLACK_TOKEN not found in config.yaml or environment"; \
		exit 1; \
	fi
	@kubectl create namespace kube-auth --dry-run=client -o yaml | kubectl apply -f -
	@if [ -n "$(DOCKER_USERNAME)" ]; then \
		helm upgrade --install kube-auth-manager ./helm/kube-auth-manager \
			--set slack.token="$(SLACK_TOKEN)" \
			--set openai.apiKey="$(OPENAI_API_KEY)" \
			--set image.repository="$(DOCKER_USERNAME)/$(IMAGE_NAME)" \
			--set image.tag="$(IMAGE_TAG)" \
			--set image.pullPolicy="Always" \
			--set cronjob.enabled=true \
			--set cronjob.schedule="$(or $(CRON_SCHEDULE),0 0 * * *)" \
			--namespace kube-auth \
			--wait; \
	else \
		$(MAKE) build; \
		helm upgrade --install kube-auth-manager ./helm/kube-auth-manager \
			--set slack.token="$(SLACK_TOKEN)" \
			--set openai.apiKey="$(OPENAI_API_KEY)" \
			--set cronjob.enabled=true \
			--set cronjob.schedule="$(or $(CRON_SCHEDULE),0 0 * * *)" \
			--namespace kube-auth \
			--wait; \
	fi
	@echo "✅ Helm CronJob deployment complete!"

# Create Kubernetes secret
secret:
	@if [ -z "$(SLACK_TOKEN)" ]; then \
		echo "❌ SLACK_TOKEN not found in config.yaml or environment"; \
		exit 1; \
	fi
	@kubectl create namespace kube-auth --dry-run=client -o yaml | kubectl apply -f -
	@if [ -n "$(OPENAI_API_KEY)" ]; then \
		kubectl create secret generic slack-credentials \
			--from-literal=slack-bot-token="$(SLACK_TOKEN)" \
			--from-literal=openai-api-key="$(OPENAI_API_KEY)" \
			--namespace=kube-auth \
			--dry-run=client -o yaml | kubectl apply -f -; \
	else \
		kubectl create secret generic slack-credentials \
			--from-literal=slack-bot-token="$(SLACK_TOKEN)" \
			--namespace=kube-auth \
			--dry-run=client -o yaml | kubectl apply -f -; \
	fi
	@echo "✅ Secret created!"

# Create OpenAI secret
openai-secret:
	@if [ -z "$(OPENAI_API_KEY)" ]; then \
		echo "❌ OPENAI_API_KEY is required"; \
		exit 1; \
	fi
	@kubectl create namespace kube-auth --dry-run=client -o yaml | kubectl apply -f -
	@kubectl create secret generic openai-credentials \
		--from-literal=openai-api-key="$(OPENAI_API_KEY)" \
		--namespace=kube-auth \
		--dry-run=client -o yaml | kubectl apply -f -
	@echo "✅ OpenAI secret created!"

# Install dependencies
install:
	@echo "📦 Installing Python dependencies..."
	@if [ -d "venv" ]; then \
		. venv/bin/activate && cd src && pip install -r requirements.txt; \
	else \
		python3 -m venv venv; \
		. venv/bin/activate && cd src && pip install -r requirements.txt; \
	fi
	@echo "✅ Dependencies installed!"

# Test Slack connection locally
test:
	@echo "🧪 Testing Slack connection..."
	@if [ -d "venv" ]; then \
		if [ -f "config.yaml" ]; then \
			echo "📝 Using config.yaml for configuration"; \
		fi; \
		. venv/bin/activate && cd src && python main.py; \
	else \
		echo "❌ Virtual environment not found. Run 'make install' first."; \
		exit 1; \
	fi

# Create test users and service accounts only (no Slack, no cleanup)
users-create:
	@echo "👥 Creating test users and service accounts..."
	@if [ -d "venv" ]; then \
		if [ -f "config.yaml" ]; then \
			echo "📝 Using config.yaml for configuration"; \
		fi; \
		CREATE_TEST_USERS_ONLY=true . venv/bin/activate && cd src && python main.py; \
	else \
		echo "❌ Virtual environment not found. Run 'make install' first."; \
		exit 1; \
	fi

# Clean up test users and service accounts
users-clean:
	@echo "🧹 Cleaning up test users and service accounts..."
	@if [ -d "venv" ]; then \
		if [ -f "config.yaml" ]; then \
			echo "📝 Using config.yaml for configuration"; \
		fi; \
		CLEANUP_TEST_RESOURCES=true . venv/bin/activate && cd src && python main.py; \
	else \
		echo "❌ Virtual environment not found. Run 'make install' first."; \
		exit 1; \
	fi

# View application logs (watches until completion)
logs:
	@echo "📝 Waiting for pod and streaming logs..."
	@echo "⏳ Waiting for job pod to be created (max 60 seconds)..."
	@pod_name=""; \
	timeout=60; \
	while [ $$timeout -gt 0 ]; do \
		pod_name=$$(kubectl get pod -n kube-auth -l job-name=kube-auth-health-check -o jsonpath='{.items[0].metadata.name}' 2>/dev/null); \
		if [ -n "$$pod_name" ]; then \
			echo "✅ Found pod: $$pod_name"; \
			break; \
		fi; \
		sleep 2; \
		timeout=$$((timeout - 2)); \
	done; \
	if [ -z "$$pod_name" ]; then \
		echo "❌ No pod found after 60 seconds. Run 'make status' to check deployment status."; \
		exit 1; \
	fi; \
	pod_phase=$$(kubectl get pod $$pod_name -n kube-auth -o jsonpath='{.status.phase}' 2>/dev/null); \
	if [ "$$pod_phase" = "Succeeded" ] || [ "$$pod_phase" = "Failed" ]; then \
		echo "📄 Pod has completed ($$pod_phase). Showing logs:"; \
		kubectl logs $$pod_name -n kube-auth -c slack-notifier --tail=100; \
		exit 0; \
	fi; \
	echo "⏳ Waiting for slack-notifier container to be ready (max 30 seconds)..."; \
	timeout=30; \
	while [ $$timeout -gt 0 ]; do \
		container_ready=$$(kubectl get pod $$pod_name -n kube-auth -o jsonpath='{.status.containerStatuses[?(@.name=="slack-notifier")].ready}' 2>/dev/null); \
		if [ "$$container_ready" = "true" ]; then \
			break; \
		fi; \
		container_state=$$(kubectl get pod $$pod_name -n kube-auth -o jsonpath='{.status.containerStatuses[?(@.name=="slack-notifier")].state.waiting.reason}' 2>/dev/null); \
		if [ -n "$$container_state" ]; then \
			echo "⏳ Container state: $$container_state ($$timeout seconds remaining)"; \
		fi; \
		sleep 2; \
		timeout=$$((timeout - 2)); \
	done; \
	echo "📺 Streaming logs (press Ctrl+C to stop watching, logs will continue until job completes)..."; \
	kubectl logs -f $$pod_name -n kube-auth -c slack-notifier

# Check deployment status
status:
	@echo "📊 Deployment status:"
	@kubectl get all -n kube-auth
	@echo ""
	@echo "Job details:"
	@kubectl describe job kube-auth-health-check -n kube-auth

# Check Helm release status
helm-status:
	@echo "📊 Helm release status:"
	@helm status kube-auth-manager -n kube-auth

# Clean up all resources (kubectl)
clean:
	@echo "🧹 Cleaning up resources..."
	@kubectl delete -k k8s/ --ignore-not-found=true
	@echo "✅ Cleanup complete!"

# Clean up Helm release
helm-clean:
	@echo "🧹 Cleaning up Helm release..."
	@helm uninstall kube-auth-manager -n kube-auth --ignore-not-found
	@echo "✅ Helm cleanup complete!"

# Create config.yaml from example
config:
	@echo "📝 Creating config.yaml from example..."
	@if [ -f "config.yaml" ]; then \
		echo "⚠️  config.yaml already exists!"; \
	else \
		cp config.yaml.example config.yaml; \
		echo "✅ config.yaml created from example"; \
		echo ""; \
		echo "📝 Next steps:"; \
		echo "   1. Edit config.yaml with your actual values"; \
		echo "   2. config.yaml is in .gitignore and will NOT be committed"; \
	fi
