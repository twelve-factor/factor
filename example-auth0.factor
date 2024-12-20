# after editing store this file at ~/.factor
[ngrok]
token = "..."

[id]
default_provider = "auth0"

[[id.providers]]
name = "auth0"
provider = "auth0"
# replace <identifier> with your assigned id
issuer = "https://<identifier>.us.auth0.com"

# the application associated with this client needs the following permissions:
#   "read:resource_servers",
#   "create:resource_servers",
#   "update:resource_servers",
#   "delete:resource_servers",
#   "read:client_grants",
#   "create:client_grants",
#   "update:client_grants",
#   "delete:client_grants"
#   "read:clients",
#   "create:clients",
#   "update:clients",
#   "delete:clients"
client_id = "..."
client_secret = "..."
