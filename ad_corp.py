import sys
import config


class CompanyDirectory(object):

    def __init__(self, azure_cred, config, logger):
        self.config = config
        self.logger = logger
        self.az = azure_cred

    def get_aws_group(self, k8s_ad_group):
        acct = k8s_ad_group.split('-')[2:]
        aws_group = '-'.join(acct)
        return aws_group

    def get_IAM_name(self, user_mail):
        iam_name = ""
        try:
            iam_name = str(user_mail).split("@")[0].replace(".", "")
        except Exception as error:
            self.logger.exception(error)
        return str(iam_name)

    def get_all_aws_groups(self, account):
        azure = self.az
        result = {}
        for group in azure.groups.list():
            try:
                if str(group.display_name).startswith('aws') and f"-{account}-" in str(group.display_name):
                    result.update(
                        {str(group.display_name): str(group.object_id)})
                elif str(group.display_name).startswith('aws') and "-common-" in str(group.display_name):
                    if account[-1] == "p" and "-staging" not in str(group.display_name):
                        result.update(
                            {str(group.display_name): str(group.object_id)})
                    elif account[-1] == "s":
                        result.update(
                            {str(group.display_name): str(group.object_id)})
            except Exception as error:
                self.logger.exception(error)
        return result

    def get_AD_group_members(self, object):
        members = []
        azure = self.az
        for member in azure.groups.get_group_members(object):
            try:
                if not member.mail:
                    members.append(member.display_name.lower())
                else:
                    members.append(self.get_IAM_name(member.mail).lower())
            except Exception:
                pass
        return members


    def get_account_info(self):
        azure = self.az
        result = {}
        accounts = self.config.aws_accounts

        for group in azure.groups.list():
            try:
                name = str(group.display_name)
                account_map = name.split('-')[1]
                group_dict = eval(str(group))
                account_number = str(group_dict['additional_properties']['description'])

                if isinstance(accounts, str) and account_map not in result:
                    if accounts == "PRODUCTION":
                        if name.startswith('aws') and account_map[-1] == 'p':
                            result.update({account_map: account_number})
                    if accounts == "ALL":
                        if name.startswith('aws') and account_map != "common":
                            result.update({account_map: account_number})
                elif isinstance(accounts, list) and account_map not in result:
                    if name.startswith('aws') and account_map in self.config.aws_accounts:
                        result.update({account_map: account_number})

            except Exception:
                pass

        result = {k: v for k, v in result.items() if not v == 'None' and k not in self.config.sync_exclude_accounts}
        #result = {k: v for k, v in result.items() if not v == 'None' and k in self.config.sync_enabled_accounts}
        return result
