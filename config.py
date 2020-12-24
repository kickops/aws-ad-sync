import os 

slack_uri = "<slack_uri>"
error_slack_uri = "https://hooks.slack.com/services/<ERROR-URI>"
encrypted_azure_client_id = os.environ['encrypted_azure_client_id']
encrypted_azure_tenant = os.environ['encrypted_azure_scrt']
encrypted_azure_scrt = os.environ['encrypted_azure_tenant']
azure_resource = "https://graph.windows.net"
sync_exclude_accounts = ['xsredp', 'cdvltp', 'vgpyrp']
aws_assume_role = 'sync_role'
aws_users_whitelist = ['user1' ,'admin']
exclusion_group = 'exclusivegroup'
opsworks_exclude_groups = 'exception-group'
deletion_exclude = ['rpre', 'vltrep', 'pghyrp']

""" 
You can now control what accounts should be sync'ed. Please see below examples
Examples:
    aws_accounts = ['wes', 'trcoes', 'kjitp', 'hgfusp'] --> list of accounts to process
    aws_accounts = 'PRODUCTION'  --> Only the AWS prod accounts
    aws_accounts = 'ALL'  --> All aws accounts including staging & production
"""

aws_accounts = 'PRODUCTION'
