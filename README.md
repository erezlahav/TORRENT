# Custom Torrent P2P Client and Tracker

This repository contains a custom-designed torrent-like peer-to-peer (P2P) file sharing system written in Python.  

---

## Overview

The system implements a custom BitTorrent-inspired protocol, including:
- Peer-to-peer architecture: every peer acts as both a downloader and seeder.
- Smart piece selection: rarest-piece-first algorithm to maximize swarm efficiency.
- Custom tracker: maintains peer lists, piece availability (bitfields), and optimizes peer discovery.
- Hybrid encryption: RSA for secure key exchange combined with AES.
- File integrity: piece-level hashing and verification to prevent corruption.
- User management: registration, login, password management, and optional email verification.

---

---

## Architecture

**Tracker Server**
- Stores metadata about available peers and the pieces they hold.
- Responds to peer announcements and keeps track of swarm health.
- Performs piece rarity calculations for optimal distribution.

**Peer Client**
- Connects to the tracker to register and receive a list of peers.
- Exchanges pieces directly with other peers over TCP.
- Verifies received pieces against expected hashes.
- Uploads pieces to other peers while downloading.

---
