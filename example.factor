# after editing store this file at ~/.factor
# [ngrok]
# token = "..."

[id]
default_provider = "local"

[[id.providers]]
name = "local"
provider = "local"

iss = "http://localhost:5000"
# for ngrok, change iss to the below
# iss = "$NGROK_URL"

# secret = "" # base64 encoded bootstrap secret -> openssl rand -base64 32
