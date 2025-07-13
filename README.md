# Custom Torrent P2P Client and Tracker

This repository contains a custom-designed torrent-like peer-to-peer (P2P) file sharing system written in Python.  
The project demonstrates advanced networking concepts, low-level socket programming, multi-threading, encrypted communication, and efficient distributed file sharing.

---

## Overview

The system implements a simplified BitTorrent-inspired protocol, including:
- Peer-to-peer architecture: every peer acts as both a downloader and uploader.
- Smart piece selection: rarest-piece-first algorithm to maximize swarm efficiency.
- Custom tracker: maintains peer lists, piece availability (bitfields), and optimizes peer discovery.
- Hybrid encryption: RSA for secure key exchange combined with AES for fast data transfer encryption.
- Multi-threaded design: separate threads for upload, download, and tracker communication with proper synchronization.
- File integrity: piece-level hashing and verification to prevent corruption.
- User management: registration, login, password management, and optional email verification.

---

## Technical Highlights

- Written in Python using raw TCP sockets and the `select` module for non-blocking I/O.
- Tracker and peer implemented as separate modules for modularity and clear responsibilities.
- Custom peer protocol: handshake, bitfield exchange, piece request/response.
- Support for simultaneous connections and parallel piece downloads.
- Encrypted communication channel to ensure confidentiality and authenticity.
- Basic system call simulation for file I/O handling and piece storage.

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
