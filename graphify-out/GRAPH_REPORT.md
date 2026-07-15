# Graph Report - ssl-certs-management  (2026-07-15)

## Corpus Check
- 60 files · ~67,377 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 623 nodes · 770 edges · 72 communities (50 shown, 22 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a7b3f402`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Conversion & Notification Core|Conversion & Notification Core]]
- [[_COMMUNITY_Certificate Management|Certificate Management]]
- [[_COMMUNITY_Database Models & CSR|Database Models & CSR]]
- [[_COMMUNITY_Backup System|Backup System]]
- [[_COMMUNITY_UI Components|UI Components]]
- [[_COMMUNITY_Application Core|Application Core]]
- [[_COMMUNITY_Model Design Rationale|Model Design Rationale]]
- [[_COMMUNITY_Sectigo Integration|Sectigo Integration]]
- [[_COMMUNITY_Settings Routes|Settings Routes]]
- [[_COMMUNITY_Test Certificate Generation|Test Certificate Generation]]
- [[_COMMUNITY_Logger Reconfiguration|Logger Reconfiguration]]
- [[_COMMUNITY_Notification Channels|Notification Channels]]
- [[_COMMUNITY_Test Notifications|Test Notifications]]
- [[_COMMUNITY_SMTP Testing|SMTP Testing]]
- [[_COMMUNITY_Theme System|Theme System]]
- [[_COMMUNITY_Alert Instances|Alert Instances]]
- [[_COMMUNITY_Docker Entrypoint|Docker Entrypoint]]
- [[_COMMUNITY_Alert Acknowledgment|Alert Acknowledgment]]
- [[_COMMUNITY_Alert Settings|Alert Settings]]
- [[_COMMUNITY_Alert Deletion|Alert Deletion]]
- [[_COMMUNITY_Alert Instance Deletion|Alert Instance Deletion]]
- [[_COMMUNITY_General Settings|General Settings]]
- [[_COMMUNITY_Notification Settings|Notification Settings]]
- [[_COMMUNITY_Alert Pause|Alert Pause]]
- [[_COMMUNITY_Alert Toggle|Alert Toggle]]
- [[_COMMUNITY_Alert Resume|Alert Resume]]
- [[_COMMUNITY_Backup Schedule|Backup Schedule]]
- [[_COMMUNITY_Alert Save|Alert Save]]
- [[_COMMUNITY_Sidebar Navigation|Sidebar Navigation]]
- [[_COMMUNITY_Login UI|Login UI]]
- [[_COMMUNITY_Package Metadata|Package Metadata]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]

## God Nodes (most connected - your core abstractions)
1. `SSL Certificate Manager` - 16 edges
2. `get_logger()` - 14 edges
3. `SSL Certificate Manager` - 13 edges
4. `Setting` - 12 edges
5. `What You Must Do When Invoked` - 12 edges
6. `What You Must Do When Invoked` - 12 edges
7. `What You Must Do When Invoked` - 12 edges
8. `User` - 10 edges
9. `check_and_send_alerts()` - 10 edges
10. `/graphify` - 10 edges

## Surprising Connections (you probably didn't know these)
- `Server-Rendered UI with JSON Endpoints` --semantically_similar_to--> `Bootstrap-Based UI`  [INFERRED] [semantically similar]
  .github/copilot-instructions.md → templates/base.html
- `Startup-Driven Background Jobs` --semantically_similar_to--> `Scheduled Backup System`  [INFERRED] [semantically similar]
  .github/copilot-instructions.md → templates/settings/backup.html
- `Session Lock Feature` --references--> `SSL Certificate Manager`  [INFERRED]
  templates/settings/general.html → .github/copilot-instructions.md
- `Lazy Expiry State Refresh Pattern` --rationale_for--> `Certificate Management Feature`  [INFERRED]
  .github/copilot-instructions.md → README.md
- `Drag-and-Drop File Upload` --references--> `Certificate Management Feature`  [INFERRED]
  templates/certificates/add.html → README.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Architecture Design Rationale** — github_copilot_instructions_flask_app_factory, github_copilot_instructions_no_service_layer, github_copilot_instructions_split_persistence, github_copilot_instructions_settings_table_pattern, github_copilot_instructions_server_rendered_ui [INFERRED 0.95]
- **Core Application Features** — readme_md_certificate_management, readme_md_alert_system, readme_md_format_conversion, readme_md_backup_restore, readme_md_csr_generation [EXTRACTED 1.00]
- **Frontend UI Components** — base_html_bootstrap_ui, list_html_datatables, list_html_sweetalert_delete, add_html_drag_drop_upload, dashboard_html_expiry_chart [INFERRED 0.85]

## Communities (72 total, 22 thin omitted)

### Community 0 - "Conversion & Notification Core"
Cohesion: 0.08
Nodes (25): AlertInstance, Tracks active/firing alerts for certificates.     Allows pausing/resuming alerts, _auto_resolve_alerts(), _build_message(), check_and_send_alerts(), _cleanup_duplicate_alerts(), Automatically resolve alerts for certificates that are no longer expiring or hav, Resolve all alert instances for a certificate except the current applicable rule (+17 more)

### Community 1 - "Certificate Management"
Cohesion: 0.10
Nodes (20): is_supported_file(), Check if the file extension is supported., Certificate, add_cert(), api_list(), delete_cert(), download_cert(), edit_cert() (+12 more)

### Community 2 - "Database Models & CSR"
Cohesion: 0.11
Nodes (18): CSRConfig, CSRRequest, CSR Configuration template model., CSR Request model to track generated CSRs., ensure_csr_directory(), _generate_cnf_content(), generate_csr(), get_csr_storage_path() (+10 more)

### Community 3 - "Backup System"
Cohesion: 0.15
Nodes (16): backup_certificates(), backup_database(), cleanup_old_backups(), ensure_backup_dir(), get_timestamp(), Create a SQL backup of the database.     Supports both SQLite and MariaDB/MySQL., Ensure the backup directory exists., Get current timestamp for backup filenames. (+8 more)

### Community 4 - "UI Components"
Cohesion: 0.05
Nodes (41): Drag-and-Drop File Upload, Alert State Management, Scheduled Backup System, Bootstrap-Based UI, Database Migration System, Interactive Format Converter, CSR Config Templates, Certificate Expiry Timeline Chart (+33 more)

### Community 5 - "Application Core"
Cohesion: 0.21
Nodes (12): create_app(), load_user(), SSL Certificate Manager Application A Flask-based web application for managing S, Load user by ID for Flask-Login., Setup background scheduler for certificate alert checks and scheduled backups., _setup_scheduler(), get_backup_schedule(), Get backup schedule settings.          Returns:         dict with schedule setti (+4 more)

### Community 6 - "Model Design Rationale"
Cohesion: 0.12
Nodes (12): User model for authentication., Hash and set the user's password., Check if the provided password matches the hash., User, logout(), profile(), Authentication routes., Verify current user's password for session unlock. (+4 more)

### Community 7 - "Sectigo Integration"
Cohesion: 0.11
Nodes (24): Exception, _cleanup_sectigo_temp(), _get_sectigo_temp_path(), Get temp file path for a session., Clean up temp file for a session., Fetch certificates from Sectigo using SSL ID.     Returns the downloaded certifi, Download the combined certificate file., sectigo_download_file() (+16 more)

### Community 8 - "Settings Routes"
Cohesion: 0.10
Nodes (19): delete_alert(), delete_alert_instance(), delete_backup(), delete_notification(), notifications(), Settings, Alert Rules, and Notification Channel routes., Delete an alert rule., Toggle an alert rule on/off. (+11 more)

### Community 9 - "Test Certificate Generation"
Cohesion: 0.83
Nodes (3): generate_cert(), generate_cert_with_san(), generate_certs.sh script

### Community 10 - "Logger Reconfiguration"
Cohesion: 0.50
Nodes (4): Swap the file handler at runtime when the user changes settings.     Returns (su, reconfigure_logging(), Save general settings., save_settings()

### Community 11 - "Notification Channels"
Cohesion: 0.22
Nodes (8): Backup utilities for SSL Certificate Manager. Supports certificate backup (ZIP), AlertLog, AlertRule, NotificationChannel, Seed default settings and alert rules if they don't exist., _seed_defaults(), Setting, Notification system for certificate expiry alerts. Supports: Email (SMTP), Slack

### Community 12 - "Test Notifications"
Cohesion: 0.50
Nodes (4): Send a test notification through a channel to verify configuration., send_test_notification(), Send a test notification., test_notification()

### Community 13 - "SMTP Testing"
Cohesion: 0.50
Nodes (4): Test SMTP connection and send a test email without requiring a saved channel., test_smtp_connection(), Test SMTP settings without saving the channel first., test_smtp()

### Community 14 - "Theme System"
Cohesion: 0.67
Nodes (3): User Theme System, Theme Support Migration, Theme Preferences UI

### Community 15 - "Alert Instances"
Cohesion: 0.06
Nodes (31): Architecture & Knowledge Graph, Background Jobs & Scheduling, Build and Run, Code Style, Common Issues, Configuration, Contributing, Database Options (+23 more)

### Community 21 - "Alert Deletion"
Cohesion: 0.08
Nodes (24): For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only, /graphify, Honesty Rules, Interpreter guard for subcommands, Part A - Structural extraction for code files (+16 more)

### Community 22 - "Alert Instance Deletion"
Cohesion: 0.08
Nodes (24): For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only, /graphify, Honesty Rules, Interpreter guard for subcommands, Part A - Structural extraction for code files (+16 more)

### Community 24 - "Notification Settings"
Cohesion: 0.08
Nodes (24): For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only, /graphify, Honesty Rules, Interpreter guard for subcommands, Part A - Structural extraction for code files (+16 more)

### Community 26 - "Alert Toggle"
Cohesion: 0.09
Nodes (21): Application structure, Background behavior, Backup scheduling, Build, test, and run commands, Callflow visualizations, Configuration and environment, Core domain logic (utility modules), CSR and openssl integration (+13 more)

### Community 27 - "Alert Resume"
Cohesion: 0.14
Nodes (19): _build_key_info(), _extract_cert_details(), extract_certificate_chain(), get_file_extension(), _get_name_attr(), parse_certificate(), Certificate parsing utilities. Supports: PEM, CRT, CER, DER, PFX/P12, KEY files., Build info dict for a private key file. (+11 more)

### Community 28 - "Backup Schedule"
Cohesion: 0.12
Nodes (16): convert_certificate(), _create_jks_keystore(), _extract_key_from_pem(), get_output_formats(), _load_jks_keystore(), Create a JKS keystore from a certificate and optional private key.          Args, Convert a certificate from one format to another.      Args:         file_data:, Get available output formats for a given input format. (+8 more)

### Community 34 - "Community 34"
Cohesion: 0.15
Nodes (12): Alternative: Manual Migration Inside Running Container, Database Volume Issues, Docker Deployment Guide, Environment Variables, Preserving Existing Data, Rebuilding the Container with Theme Support, Step 1: Stop the Running Container, Step 2: Rebuild the Image (+4 more)

### Community 35 - "Community 35"
Cohesion: 0.17
Nodes (11): delete_config(), delete_csr(), get_config(), list_configs(), CSR (Certificate Signing Request) generation routes., Get a config template details., Delete a config template., View CSR content and details. (+3 more)

### Community 36 - "Community 36"
Cohesion: 0.27
Nodes (7): Certificate conversion utilities. Supports conversion between PEM, DER, CRT, CER, get_logger(), Centralized logging configuration for SSL Cert Manager. Provides file + console, Get a child logger under the certmanager namespace., index(), Certificate conversion routes., Conversion utility page.

### Community 37 - "Community 37"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 38 - "Community 38"
Cohesion: 0.31
Nodes (6): Config, migrate_database(), Database Migration: Add theme column to users table  This script adds the theme, Add theme column to users table if it doesn't exist., migrate(), Apply migration to add CASCADE delete constraints.

### Community 39 - "Community 39"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 40 - "Community 40"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 41 - "Community 41"
Cohesion: 0.22
Nodes (8): Alternative Solution (Option 2) - For Higher Load, Alternative Solution (Option 3) - Separate Scheduler Container, Duplicate Alert Notification Fix, Prevention, Problem, Root Cause, Solution Applied (Option 1), Testing

### Community 42 - "Community 42"
Cohesion: 0.29
Nodes (8): escape_sql_string(), generate_create_table(), generate_insert_statement(), generate_sql_dump(), Generate a MySQL/MariaDB compatible SQL dump from the database.     Works with b, Generate CREATE TABLE statement for a model., Generate INSERT statement for a record., Escape a string for SQL insertion.

### Community 43 - "Community 43"
Cohesion: 0.25
Nodes (6): Build, test, and run commands, Configuration, Database Migrations, graphify, High-level architecture, Key repository-specific conventions

### Community 44 - "Community 44"
Cohesion: 0.25
Nodes (7): Creating a New Migration, Current Migrations, Database Migrations, How It Works, Migration Naming Convention, Running Migrations Manually, When Are Migrations Needed?

### Community 45 - "Community 45"
Cohesion: 0.33
Nodes (6): delete_backup(), get_backup_path(), Get the backup directory path from settings or use default., Delete a specific backup file.          Args:         filename: Name of the back, download_backup(), Download a backup file.

### Community 46 - "Community 46"
Cohesion: 0.33
Nodes (6): format_file_size(), list_backups(), List all available backups.          Returns:         dict: {'cert_backups': lis, Format file size in human-readable format., backup(), Backup management page.

### Community 47 - "Community 47"
Cohesion: 0.33
Nodes (5): For /graphify explain, For /graphify path, graphify reference: query, path, explain, Step 0 — Constrained query expansion (REQUIRED before traversal), Step 1 — Traversal

### Community 48 - "Community 48"
Cohesion: 0.33
Nodes (5): For /graphify explain, For /graphify path, graphify reference: query, path, explain, Step 0 — Constrained query expansion (REQUIRED before traversal), Step 1 — Traversal

### Community 49 - "Community 49"
Cohesion: 0.33
Nodes (5): For /graphify explain, For /graphify path, graphify reference: query, path, explain, Step 0 — Constrained query expansion (REQUIRED before traversal), Step 1 — Traversal

### Community 50 - "Community 50"
Cohesion: 0.50
Nodes (3): For /graphify add, For --watch, graphify reference: add a URL and watch a folder

### Community 51 - "Community 51"
Cohesion: 0.50
Nodes (3): For git commit hook, For native CLAUDE.md integration, graphify reference: commit hook and native CLAUDE.md integration

### Community 52 - "Community 52"
Cohesion: 0.50
Nodes (3): For --cluster-only, For --update (incremental re-extraction), graphify reference: incremental update and cluster-only

### Community 53 - "Community 53"
Cohesion: 0.50
Nodes (3): For /graphify add, For --watch, graphify reference: add a URL and watch a folder

### Community 54 - "Community 54"
Cohesion: 0.50
Nodes (3): For git commit hook, For native CLAUDE.md integration, graphify reference: commit hook and native CLAUDE.md integration

### Community 55 - "Community 55"
Cohesion: 0.50
Nodes (3): For --cluster-only, For --update (incremental re-extraction), graphify reference: incremental update and cluster-only

### Community 56 - "Community 56"
Cohesion: 0.50
Nodes (3): For /graphify add, For --watch, graphify reference: add a URL and watch a folder

### Community 57 - "Community 57"
Cohesion: 0.50
Nodes (3): For git commit hook, For native CLAUDE.md integration, graphify reference: commit hook and native CLAUDE.md integration

### Community 58 - "Community 58"
Cohesion: 0.50
Nodes (3): For --cluster-only, For --update (incremental re-extraction), graphify reference: incremental update and cluster-only

## Knowledge Gaps
- **218 isolated node(s):** `docker-entrypoint.sh script`, `ssl-cert-manager`, `graphify`, `Usage`, `What graphify is for` (+213 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **22 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `get_logger()` connect `Community 36` to `Certificate Management`, `Community 35`, `Application Core`, `Model Design Rationale`, `Sectigo Integration`, `Settings Routes`, `Notification Channels`, `Alert Resume`?**
  _High betweenness centrality (0.030) - this node is a cross-community bridge._
- **Why does `Setting` connect `Notification Channels` to `Certificate Management`, `Community 35`, `Community 36`, `Application Core`, `Settings Routes`, `Logger Reconfiguration`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **Why does `User` connect `Model Design Rationale` to `Notification Channels`, `Application Core`?**
  _High betweenness centrality (0.010) - this node is a cross-community bridge._
- **What connects `Sectigo Certificate Download Utilities. Downloads SSL certificates from Sectigo`, `Custom exception for Sectigo download errors.`, `Download a certificate from Sectigo using SSL ID.          Args:         ssl_id:` to the rest of the system?**
  _359 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Conversion & Notification Core` be split into smaller, more focused modules?**
  _Cohesion score 0.07692307692307693 - nodes in this community are weakly interconnected._
- **Should `Certificate Management` be split into smaller, more focused modules?**
  _Cohesion score 0.09881422924901186 - nodes in this community are weakly interconnected._
- **Should `Database Models & CSR` be split into smaller, more focused modules?**
  _Cohesion score 0.10526315789473684 - nodes in this community are weakly interconnected._