# API Endpoints

This document provides an overview of the available API endpoints in the nftables parser backend. These endpoints are used by the frontend to interact with nftables configurations.

---

## Overview

The backend API is structured into multiple modules, each responsible for a specific part of nftables configuration. These modules are exposed through the following base endpoints:

- `/tables`
- `/chains`
- `/rules`
- `/sets`
- `/maps`
- `/service`

Each endpoint corresponds to a module in the backend and handles operations related to that component.

---

## Endpoint Details

### /tables
Handles operations related to nftables tables.

**Responsibilities:**
- Create and manage tables
- Retrieve table information

---

### /chains
Manages chains within tables.

**Responsibilities:**
- Create and delete chains
- Configure chain behavior

---

### /rules
Handles firewall rules.

**Responsibilities:**
- Add new rules
- Update existing rules
- Delete rules

---

### /sets
Manages nftables sets.

**Responsibilities:**
- Create and manage sets
- Store grouped data for rules

---

### /maps
Handles nftables maps.

**Responsibilities:**
- Define key-value mappings
- Support advanced rule configurations

---

### /service
Provides utility and service-related operations.

**Responsibilities:**
- Backend service handling
- Supporting API functionality

---

## How It Connects

The frontend communicates with these endpoints via API requests. Each request is routed to the corresponding module, processed, and a response is returned back to the frontend.

**Flow:**

Frontend → API Endpoint → Parser Module → Response → Frontend
