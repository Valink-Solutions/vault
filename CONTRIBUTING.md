# ChunkVault Backend - Vault: Contributing

Thank you for your interest in contributing to Vault. By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

This document outlines the process for contributing to the project and the expectations we have for all contributors. Please read through this document before making a contribution.

## Table of Contents

*   [Getting Started](#getting-started)
    *   [Generate Private and Public Keys](#generate-private-and-public-keys)
*   [Pull Requests](#pull-requests)
*   [Bug Reports and Feature Requests](#bug-reports-and-feature-requests)
*   [Coding Guidelines](#coding-guidelines)
*   [Communication](#communication)

## Getting Started

Ensure you have [Rust and Cargo](https://www.rust-lang.org/) installed before continuing.

1.  Fork the repository on GitHub.
2.  Clone your fork to your local machine: `git clone https://github.com/Valink-Solutions/vault.git`
3.  Add the original repository as an upstream remote: `git remote add upstream https://github.com/Valink-Solutions/vault.git`
4.  Create a new branch for your feature or bugfix: `git checkout -b my-feature-branch`
5.  Make your changes and commit them with a descriptive commit message.
6.  Push your changes to your fork on GitHub.
7.  Open a pull request against the upstream `main` branch.

### Generate Keys

Before you can run the application, you will need to generate a private and public key pair using OpenSSL:

sh

```sh
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

This will create a private key file (`private_key.pem`) and a public key file (`public_key.pem`).

### Initialize PostgreSQL Database using Docker

Before running the application, ensure you have a PostgreSQL database set up using Docker with the following steps:

1. Install [Docker](https://www.docker.com/get-started) if you haven't already.

2. Pull the latest PostgreSQL image and run it as a container using the following command:

```sh
docker run --name vault-postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=vault -p 5432:5432 -d postgres:latest
```

Replace `password` with your desired password for the PostgreSQL user. This command will create a new PostgreSQL container with the `vault` database and expose it on the default port `5432`.

3. Run the database migrations located in the `migrations` folder to set up the necessary tables:

```sh
sqlx migrate run
```

You should now have a PostgreSQL database set up for the project using Docker.

### Set up Environment Variables

Create a `.env` file in the root of the project directory with the following content:

sh

```sh
DATABASE_URL="postgres://postgres:password@localhost:5432/vault"
PRIVATE_KEY_PATH="./private_key.pem"
PUBLIC_KEY_PATH="./public_key.pem"
STORAGE_TYPE="local"
LOCAL_STORAGE_PATH="./testing_data"
```

Replace `password` with your PostgreSQL password. This file will be used to store sensitive configuration values that should not be committed to the repository.

## Pull Requests

*   Before submitting a pull request, ensure your changes compile and pass all tests.
*   Keep your pull requests focused on a single feature or bugfix. If you have multiple features or bugfixes, submit separate pull requests for each.
*   Write a clear and concise description of the changes you made in the pull request.
*   If your pull request resolves an existing issue, reference the issue number in the description.
*   Update the documentation if necessary to reflect your changes.
*   Be open to feedback from the maintainers and other contributors, and be prepared to make changes to your pull request if requested.

## Bug Reports and Feature Requests

*   Before submitting a bug report or feature request, search the existing issues to see if it has already been reported or requested.
*   When submitting a bug report, include as much information as possible to help us reproduce the issue. Include your system information, steps to reproduce, and any error messages.
*   When submitting a feature request, provide a clear and detailed description of the feature, including the motivation for the feature and any use cases.

## Coding Guidelines

*   Follow the [Rust coding guidelines](https://rust-lang.github.io/api-guidelines/) and the [Actix best practices](https://actix.rs/docs/).
*   Use clear and descriptive variable and function names.
*   Write code that is easy to understand and maintain.
*   Include comments for complex or non-obvious code.
*   Ensure your code is efficient and optimized for performance.
*   Write and update tests for your code.

## Communication

*   Be respectful and considerate of other contributors.
*   Keep discussions focused on the project and its goals.
*   Be open to feedback and constructive criticism.

We appreciate your contributions and look forward to working together to make Vault the best it can be!