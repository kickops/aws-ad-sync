import boto3
import sys


class AwsUtils(object):

    def __init__(self, config, logger, iam):
        self.config = config
        self.logger = logger
        self.iam = iam.meta.client
        self.resource = iam

    def get_AWS_group_members(self, group_name):
        """ Returns a list of members part of an IAM group """
        iam = self.iam
        members = []
        try:
            group_obj = iam.get_group(GroupName=group_name)
            members = [user['UserName'] for user in group_obj['Users']]
        except Exception as err:
            if err.response['Error']['Code'] == 'NoSuchEntity':
                members = []
            else:
                self.logger.exception(err)
        return members

    def add_user_to_group(self, group, user):
        iam = self.iam
        user_exist = self.check_if_user_exists(user)
        if not user_exist:
            self.create_iam_user(user)
        try:
            iam.add_user_to_group(GroupName=group, UserName=user)
        except Exception as error:
            self.logger.exception(error)

    def check_if_user_exists(self, username):
        iam = self.iam
        found = False
        try:
            iam.get_user(UserName=username)
            found = True
        except Exception as err:
            if err.response['Error']['Code'] == 'NoSuchEntity':
                found = False
        return found

    def create_iam_user(self, username):
        iam = self.iam
        try:
            iam.create_user(UserName=username)
        except Exception as error:
            self.logger.exception(error)

    def delete_iam_user(self, username):
        iam = self.iam
        try:
            iam.delete_user(UserName=username)
        except Exception as error:
            self.logger.exception(error)

    def add_users_to_group(self, group, user_list):
        iam = self.iam
        for user in user_list:
            user_exist = self.check_if_user_exists(user)
            if not user_exist:
                self.create_iam_user(user)
            try:
                iam.add_user_to_group(GroupName=group, UserName=user)
            except Exception as error:
                self.logger.exception(error)

    def remove_user_from_group(self, group, user):
        iam = self.iam
        try:
            iam.remove_user_from_group(GroupName=group, UserName=user)
        except Exception as error:
            self.logger.exception(error)

    def remove_users_from_group(self, group, user_list):
        iam = self.iam
        for user in user_list:
            try:
                iam.remove_user_from_group(GroupName=group, UserName=user)
            except Exception as error:
                self.logger.exception(error)

    def get_all_iam_users(self):
        iam = self.resource
        users = []
        try:
            user_list =  iam.users.all()
            for user in user_list:
                users.append(user.name)
        except Exception as error:
                self.logger.exception(error)
        return users

    def get_user_groups(self, user):
        iam = self.iam
        groups = []
        try:
            group_obj = iam.list_groups_for_user(UserName=user)
            groups = [group['GroupName'] for group in group_obj['Groups']]
        except Exception as error:
            self.logger.exception(error)
        return groups

    def get_access_keys(self, user):
        iam = self.iam
        access_keys = iam.list_access_keys(UserName=user)
        return access_keys['AccessKeyMetadata']


    def list_mfa_devices(self, user):
        iam = self.iam
        devices = []
        response = iam.list_mfa_devices(UserName=user)
        return response['MFADevices']


    def deactivate_mfa_device(self, user, serial):
        iam = self.iam
        response = iam.deactivate_mfa_device(UserName=user,SerialNumber=serial)

        
    def delete_virtual_mfa_device(self, user, serial):
        iam = self.iam
        self.deactivate_mfa_device(user, serial)
        response = iam.delete_virtual_mfa_device(SerialNumber=serial)


    def create_iam_users(self, user_list):
        iam = self.iam
        created_users = []
        create_failed = []
        create_error_dict = {}
        for user in user_list:
            user_exist = self.check_if_user_exists(user)
            if not user_exist:
                try:
                    iam.create_user(UserName=user)
                    created_users.append(user)
                except Exception as error:
                    create_failed.append(user)
                    create_error_dict[user] = error.response['Error']['Message']
                    self.logger.exception(error)
        return created_users, create_failed, create_error_dict


    def remove_ssh_public_keys(self, user):
        iam = self.iam
        response = iam.list_ssh_public_keys(UserName=user)
        if 'SSHPublicKeys' in response and response['SSHPublicKeys']:
            for key in response['SSHPublicKeys']:
                iam.delete_ssh_public_key(UserName=user, SSHPublicKeyId=key['SSHPublicKeyId'])


    def remove_service_specific_credentials(self, user):
        iam = self.iam
        response = iam.list_service_specific_credentials(UserName=user)
        if 'ServiceSpecificCredentials' in response and response['ServiceSpecificCredentials']:
            iam.delete_service_specific_credential(UserName=user,
                ServiceSpecificCredentialId=response['ServiceSpecificCredentials']['ServiceSpecificCredentialId'])
    
    def remove_mfa_devices(self, user):
        devices = self.list_mfa_devices(user)
        if devices:
            for device in devices:
                self.delete_virtual_mfa_device(user, device['SerialNumber'])


    def remove_from_groups(self, user):
        groups = self.get_user_groups(user)
        if groups:
            for group_name in groups:
                if group_name != self.config.exclusion_group:
                    self.remove_user_from_group(group_name, user)


    def delete_iam_users(self, user_list):
        iam = self.iam
        delete_failed = []
        deleted_users = []
        delete_error_dict = {}
        for user in user_list:
            user_exist = self.check_if_user_exists(user)
            if user_exist:
                self.remove_from_groups(user)
                self.remove_mfa_devices(user)
                self.remove_ssh_public_keys(user)
                self.remove_service_specific_credentials(user)
                self.logger.debug('user will be deleted %s' %user)
                try:
                    iam.delete_user(UserName=user)
                    deleted_users.append(user)
                except Exception as error:
                    delete_failed.append(user)
                    delete_error_dict[user] = error.response['Error']['Message']
                    self.logger.exception(error)
        return deleted_users, delete_failed, delete_error_dict

