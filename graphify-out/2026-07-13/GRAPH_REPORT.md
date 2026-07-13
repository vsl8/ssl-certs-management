# Graph Report - ssl-certs-management  (2026-06-26)

## Corpus Check
- 61 files · ~67,378 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 343 nodes · 522 edges · 20 communities (16 shown, 4 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e8026014`
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
- [[_COMMUNITY_Theme System|Theme System]]
- [[_COMMUNITY_Alert Instances|Alert Instances]]
- [[_COMMUNITY_Docker Entrypoint|Docker Entrypoint]]
- [[_COMMUNITY_Sidebar Navigation|Sidebar Navigation]]
- [[_COMMUNITY_Login UI|Login UI]]
- [[_COMMUNITY_Package Metadata|Package Metadata]]

## God Nodes (most connected - your core abstractions)
1. `get_logger()` - 14 edges
2. `SSL Certificate Manager` - 13 edges
3. `Setting` - 12 edges
4. `User` - 10 edges
5. `check_and_send_alerts()` - 10 edges
6. `backup_database()` - 9 edges
7. `refresh_cert_expiry()` - 9 edges
8. `convert_certificate()` - 9 edges
9. `Certificate` - 9 edges
10. `_send_notification()` - 9 edges

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

## Communities (20 total, 4 thin omitted)

### Community 0 - "Conversion & Notification Core"
Cohesion: 0.07
Nodes (38): create_app(), load_user(), SSL Certificate Manager Application A Flask-based web application for managing S, Load user by ID for Flask-Login., Setup background scheduler for certificate alert checks and scheduled backups., _setup_scheduler(), get_backup_schedule(), Get backup schedule settings.          Returns:         dict with schedule setti (+30 more)

### Community 1 - "Certificate Management"
Cohesion: 0.06
Nodes (40): _build_key_info(), _extract_cert_details(), extract_certificate_chain(), _get_name_attr(), parse_certificate(), Build info dict for a private key file., Extract all details from an x509 certificate object., Safely get a name attribute from x509 Name object. (+32 more)

### Community 2 - "Database Models & CSR"
Cohesion: 0.08
Nodes (29): CSRConfig, CSRRequest, CSR Configuration template model., CSR Request model to track generated CSRs., delete_config(), delete_csr(), ensure_csr_directory(), _generate_cnf_content() (+21 more)

### Community 3 - "Backup System"
Cohesion: 0.08
Nodes (37): backup_certificates(), backup_database(), cleanup_old_backups(), delete_backup(), ensure_backup_dir(), escape_sql_string(), format_file_size(), generate_create_table() (+29 more)

### Community 4 - "UI Components"
Cohesion: 0.06
Nodes (35): Drag-and-Drop File Upload, Alert State Management, Scheduled Backup System, Bootstrap-Based UI, Database Migration System, Interactive Format Converter, CSR Config Templates, Certificate Expiry Timeline Chart (+27 more)

### Community 5 - "Application Core"
Cohesion: 0.31
Nodes (6): Config, migrate_database(), Database Migration: Add theme column to users table  This script adds the theme, Add theme column to users table if it doesn't exist., migrate(), Apply migration to add CASCADE delete constraints.

### Community 6 - "Model Design Rationale"
Cohesion: 0.12
Nodes (12): User model for authentication., Hash and set the user's password., Check if the provided password matches the hash., User, logout(), profile(), Authentication routes., Verify current user's password for session unlock. (+4 more)

### Community 7 - "Sectigo Integration"
Cohesion: 0.15
Nodes (18): Exception, Fetch certificates from Sectigo using SSL ID.     Returns the downloaded certifi, sectigo_fetch_certs(), download_and_combine_certificates(), download_certificate(), download_intermediate_certificate(), download_server_certificate(), extract_dns_sans() (+10 more)

### Community 8 - "Settings Routes"
Cohesion: 0.05
Nodes (45): Swap the file handler at runtime when the user changes settings.     Returns (su, reconfigure_logging(), Send a test notification through a channel to verify configuration., Test SMTP connection and send a test email without requiring a saved channel., send_test_notification(), test_smtp_connection(), acknowledge_alert_instance(), alerts() (+37 more)

### Community 9 - "Test Certificate Generation"
Cohesion: 0.83
Nodes (3): generate_cert(), generate_cert_with_san(), generate_certs.sh script

### Community 14 - "Theme System"
Cohesion: 0.67
Nodes (3): User Theme System, Theme Support Migration, Theme Preferences UI

### Community 15 - "Alert Instances"
Cohesion: 0.07
Nodes (34): AlertInstance, AlertLog, AlertRule, init_db(), NotificationChannel, Tracks active/firing alerts for certificates.     Allows pausing/resuming alerts, Initialize database and create tables., Seed default settings and alert rules if they don't exist. (+26 more)

## Knowledge Gaps
- **19 isolated node(s):** `docker-entrypoint.sh script`, `ssl-cert-manager`, `Theme Support Migration`, `MariaDB Database Support`, `Docker Volume Persistence` (+14 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `get_logger()` connect `Conversion & Notification Core` to `Certificate Management`, `Database Models & CSR`, `Backup System`, `Model Design Rationale`, `Sectigo Integration`, `Settings Routes`, `Alert Instances`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `Setting` connect `Alert Instances` to `Conversion & Notification Core`, `Certificate Management`, `Database Models & CSR`, `Backup System`, `Settings Routes`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Why does `User` connect `Model Design Rationale` to `Conversion & Notification Core`, `Backup System`, `Alert Instances`?**
  _High betweenness centrality (0.033) - this node is a cross-community bridge._
- **What connects `SSL Certificate Manager Application A Flask-based web application for managing S`, `Load user by ID for Flask-Login.`, `Setup background scheduler for certificate alert checks and scheduled backups.` to the rest of the system?**
  _160 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Conversion & Notification Core` be split into smaller, more focused modules?**
  _Cohesion score 0.07188160676532769 - nodes in this community are weakly interconnected._
- **Should `Certificate Management` be split into smaller, more focused modules?**
  _Cohesion score 0.059800664451827246 - nodes in this community are weakly interconnected._
- **Should `Database Models & CSR` be split into smaller, more focused modules?**
  _Cohesion score 0.08064516129032258 - nodes in this community are weakly interconnected._