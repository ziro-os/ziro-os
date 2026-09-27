# Contributing to Ziro-OS

Thank you for your interest in contributing to Ziro-OS! This document provides guidelines and information for contributors.

## 🌟 Ways to Contribute

### Code Contributions
- **Core OS Development**: Kernel, init system, container runtime
- **Package Manager**: ZiroPkg features and packages
- **Developer SDK**: Tools and utilities for developers
- **Cloud Integration**: AWS, Azure, GCP deployment tools
- **Monitoring**: Observability and monitoring improvements
- **Security**: Security hardening and vulnerability fixes

### Documentation
- **Tutorials**: Step-by-step guides for users
- **API Documentation**: Technical reference materials
- **Best Practices**: Guidelines for optimal usage
- **Troubleshooting**: Common issues and solutions

### Community
- **Examples**: Sample applications and use cases
- **Plugins**: Extensions for the Ziro-OS ecosystem
- **Testing**: Quality assurance and bug reports
- **Support**: Help other users in forums and chat

## 🚀 Getting Started

### Development Environment Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/ziro-os/ziro-os.git
   cd ziro-os
   ```

2. **Install Dependencies**
   ```bash
   # Install build tools
   sudo apt-get update
   sudo apt-get install build-essential curl wget git

   # Install Go (for tools and SDK)
   wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
   sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin

   # Install container tools
   sudo apt-get install containerd.io docker.io
   ```

3. **Build Ziro-OS**
   ```bash
   # Build the complete system
   make all

   # Test in QEMU
   make dev-qemu
   ```

### Development Workflow

1. **Fork and Branch**
   ```bash
   # Fork the repository on GitHub
   # Clone your fork
   git clone https://github.com/YOUR_USERNAME/ziro-os.git
   cd ziro-os

   # Create a feature branch
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Follow the coding standards (see below)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run tests
   make test-smoke
   make test-full

   # Test specific components
   make test-container
   ```

4. **Submit Pull Request**
   ```bash
   # Commit your changes
   git add .
   git commit -m "feat: add your feature description"

   # Push to your fork
   git push origin feature/your-feature-name

   # Create pull request on GitHub
   ```

## 📋 Coding Standards

### General Guidelines
- **Clarity**: Write clear, readable code with meaningful names
- **Simplicity**: Prefer simple solutions over complex ones
- **Performance**: Consider performance implications
- **Security**: Follow security best practices
- **Documentation**: Document public APIs and complex logic

### Go Code Style
```go
// Use gofmt for formatting
gofmt -w .

// Follow effective Go guidelines
// https://golang.org/doc/effective_go.html

// Example function with proper documentation
// ProcessContainer handles container lifecycle operations.
// It returns an error if the operation fails.
func ProcessContainer(ctx context.Context, id string) error {
    // Implementation here
    return nil
}
```

### Shell Script Style
```bash
#!/bin/bash
# Use strict error handling
set -euo pipefail

# Use meaningful variable names
CONTAINER_NAME="ziro-app"
IMAGE_TAG="latest"

# Quote variables to prevent word splitting
echo "Starting container: ${CONTAINER_NAME}"

# Use functions for reusable code
function cleanup() {
    echo "Cleaning up resources..."
}
trap cleanup EXIT
```

### Commit Message Format
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

Examples:
```
feat(ziropkg): add package search functionality

Add search command to ziropkg CLI that allows users to search
for packages by name, description, and tags.

Closes #123
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions and components
2. **Integration Tests**: Test component interactions
3. **System Tests**: Test complete system functionality
4. **Performance Tests**: Benchmark and load testing

### Writing Tests

```go
// Example unit test
func TestContainerManager_Start(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    error
        wantErr bool
    }{
        {
            name:    "valid container",
            input:   "nginx:alpine",
            want:    nil,
            wantErr: false,
        },
        {
            name:    "invalid image",
            input:   "",
            want:    ErrInvalidImage,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cm := NewContainerManager()
            err := cm.Start(tt.input)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if !errors.Is(err, tt.want) {
                t.Errorf("Start() error = %v, want %v", err, tt.want)
            }
        })
    }
}
```

### Running Tests

```bash
# Run all tests
make test-full

# Run specific test categories
make test-smoke      # Basic functionality
make test-container  # Container operations
make test-security   # Security features

# Run tests with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...
```

## 📚 Documentation Guidelines

### Documentation Types

1. **API Documentation**: Generated from code comments
2. **User Guides**: Step-by-step instructions
3. **Tutorials**: Learning-oriented content
4. **Reference**: Technical specifications

### Writing Documentation

- **Clear Structure**: Use headings and sections
- **Code Examples**: Include working examples
- **Screenshots**: Visual aids where helpful
- **Links**: Reference related content
- **Updates**: Keep documentation current

### Documentation Format

```markdown
# Title

Brief description of the topic.

## Prerequisites

- Requirement 1
- Requirement 2

## Step-by-Step Instructions

### Step 1: Setup

Description of the first step.

```bash
# Example command
make setup
```

### Step 2: Configuration

Description and code example.

## Troubleshooting

Common issues and solutions.

## Next Steps

Links to related topics.
```

## 🔒 Security Guidelines

### Security Considerations

- **Input Validation**: Validate all user inputs
- **Privilege Escalation**: Use minimal required privileges
- **Secrets Management**: Never commit secrets to code
- **Dependencies**: Keep dependencies updated
- **Container Security**: Follow container security best practices

### Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead:
1. Email security@ziro-os.io with details
2. Include steps to reproduce
3. Provide impact assessment
4. Allow time for fix before disclosure

## 🏗️ Architecture Guidelines

### Design Principles

1. **Container-Native**: Everything runs in containers
2. **Minimal**: Only essential components included
3. **Secure**: Security by default
4. **Fast**: Optimized for performance
5. **Modular**: Pluggable architecture

### Component Structure

```
ziro-os/
├── kernel/          # Kernel configuration and patches
├── rootfs/          # Minimal root filesystem
├── packages/        # Package build system
├── ziropkg/         # Package manager
├── sdk/             # Developer SDK
├── monitoring/      # Observability stack
├── security/        # Security hardening
├── deploy/          # Deployment automation
└── community/       # Examples and documentation
```

## 🎯 Project Roadmap

### Current Focus Areas

1. **Performance Optimization**: Boot time and resource usage
2. **Security Hardening**: Additional security features
3. **Cloud Integration**: Better cloud provider support
4. **Developer Experience**: Improved tooling and documentation
5. **Ecosystem Growth**: More packages and plugins

### How to Get Involved

1. **Check Issues**: Look for "good first issue" labels
2. **Join Discussions**: Participate in GitHub discussions
3. **Propose Features**: Create feature request issues
4. **Review PRs**: Help review pull requests
5. **Write Documentation**: Improve existing docs

## 💬 Communication Channels

### Primary Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Discord**: Real-time chat and community support
- **Mailing List**: Development announcements

### Community Guidelines

- **Be Respectful**: Treat everyone with respect
- **Be Constructive**: Provide helpful feedback
- **Be Patient**: Allow time for responses
- **Be Inclusive**: Welcome newcomers
- **Follow Code of Conduct**: Adhere to community standards

## 🏆 Recognition

### Contributor Recognition

- **Contributors List**: All contributors listed in README
- **Release Notes**: Major contributions highlighted
- **Community Spotlight**: Featured contributors
- **Maintainer Status**: Path to becoming a maintainer

### Becoming a Maintainer

Requirements:
1. Consistent high-quality contributions
2. Deep understanding of project architecture
3. Active community participation
4. Demonstrated leadership skills
5. Commitment to project values

## 📄 License

By contributing to Ziro-OS, you agree that your contributions will be licensed under the same license as the project (MIT License).

## 🙏 Thank You

Thank you for contributing to Ziro-OS! Your contributions help make container-native computing accessible to everyone.

For questions about contributing, please:
- Create a GitHub discussion
- Join our Discord server
- Email contribute@ziro-os.io

Happy coding! 🚀