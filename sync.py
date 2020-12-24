#!/usr/bin/env python

import boto3
import config
import collections
import json
import logging
import os
import requests
import sys
import time
from ad_corp import CompanyDirectory
from botocore.config import Config
from datetime import datetime, timedelta
from aws_utils import AwsUtils
from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from lambda_support import decrypt
import multiprocessing


logger = logging.getLogger('aws_ad_accounts_sync')
aws_role_name = config.aws_assume_role
whitelisted_iam_user = config.aws_users_whitelist
sts_client = boto3.client('sts')
payer_acc_id = '<acc-id>'


def azure_auth():
    try:
        client_info = ServicePrincipalCredentials(
            client_id=decrypt(config.encrypted_azure_client_id), secret=decrypt(config.encrypted_azure_scrt), tenant=decrypt(config.encrypted_azure_tenant), resource=config.azure_resource)
        client = GraphRbacManagementClient(
            client_info, decrypt(config.encrypted_azure_tenant))
    except Exception as error:
        logger.exception(error)
        raise Exception(error)
    return client


def construct_accounts_map():
    azure_cred = azure_auth()
    azure_utils = CompanyDirectory(azure_cred, config, logger)
    aws_accounts_dict = azure_utils.get_account_info()
    return aws_accounts_dict, azure_utils


def message_slack(message, slack_uri=config.slack_uri):
    try:
        msg_string = '```%s```' %json.dumps(message, indent=4)
        payload = {'text': msg_string}

        http_response = requests.post(slack_uri, json=payload)
        e = http_response.raise_for_status()
    except Exception as e:
        print(e)
        logger.exception(error)

def get_sts_iam_object(sts_client, account_id, service, account_name):
    boto_config = Config(retries = dict(max_attempts = 10))
    role_arn = 'arn:aws:iam::%s:role/%s' % (account_id, aws_role_name)
    role_session_name = '%s_aws_reaper' % account_id
    try:
        if account_id == payer_acc_id:
            return AwsUtils(config, logger, boto3.resource('iam'))
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=role_session_name)
        credentials = assumed_role_object['Credentials']
        if service == "iam":
            client = boto3.resource(
                'iam', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],config=boto_config)
        elif service == "opsworks":
            client = boto3.client('opsworks', aws_access_key_id=credentials['AccessKeyId'],
                                  aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],config=boto_config)
        return AwsUtils(config, logger, client)
    except Exception as error:
        logger.exception(error)
        logger.exception(role_arn)
        if error.response['Error']['Code'] == "AccessDenied":
            message = collections.OrderedDict()
            message['Account_Name'] = account_name
            message['Error'] = error.response['Error']['Message']
            message_slack(message, slack_uri=config.error_slack_uri)
        else:
            raise Exception(error)


def get_whitelist_users(aws_creds):
    whitelist_users = []
    application_users = []
    exclusion_users = config.aws_users_whitelist
    if exclusion_users:
        whitelist_users.extend(exclusion_users)
    application_users = aws_creds.get_AWS_group_members(config.exclusion_group)
    if application_users:
        whitelist_users.extend(application_users)
    if config.opsworks_exclude_groups:
        ops_users = aws_creds.get_AWS_group_members(config.opsworks_exclude_groups)
        if ops_users:
            whitelist_users.extend(ops_users)
    return whitelist_users, application_users


def reconfirm_app_users(aws_creds, users_list):
    application_list = []
    for user in users_list:
        access_keys = aws_creds.get_access_keys(user)
        if access_keys:
            application_list.append(user)
    final_list = list(set(users_list) - set(application_list))
    return final_list, application_list


def make_decision(aws_creds, ad_users, iam_users, account):
    users_to_be_created = list(set(ad_users) - set(iam_users))
    created, c_failed, create_error_dict = aws_creds.create_iam_users(users_to_be_created)
    if create_error_dict:
        err_message = collections.OrderedDict()
        err_message['Account_Name'] = account
        err_message['Error'] = create_error_dict
        message_slack(err_message, slack_uri=config.error_slack_uri)

    whitelist_users, application_users = get_whitelist_users(aws_creds)
    iam_users_after_exclusion = list(set(iam_users) - set(whitelist_users))

    #Double confirm if the users considered for deletion doesnt have access keys
    removal_list, app_user_list = reconfirm_app_users(aws_creds, iam_users_after_exclusion)
    users_to_be_deleted = list(set(removal_list) - set(ad_users))

    deleted = []
    d_failed = []
    if account not in config.deletion_exclude:
        deleted, d_failed, error_dict = aws_creds.delete_iam_users(users_to_be_deleted)
        if error_dict:
            message = collections.OrderedDict()
            message['Account_Name'] = account
            message['Error'] = error_dict
            message_slack(message, slack_uri=config.error_slack_uri)
    message = collections.OrderedDict()
    message['Account_Name'] = account
    params_dict = collections.OrderedDict()
    params_dict['Application_Users'] = application_users
    params_dict['Users_with_AccessKeys'] = app_user_list
    params_dict['Whitelisted_Users'] = list(set(iam_users).intersection(config.aws_users_whitelist))
    params_dict['Creation_list'] = users_to_be_created 
    params_dict['Created_Users'] = created
    params_dict['Create_Failed'] = c_failed
    if deleted:
        params_dict['Deleted_Users'] = deleted
    if d_failed:
        params_dict['Delete_Failed'] = d_failed
    params_dict['Deletion_List'] = users_to_be_deleted

    for key,value in params_dict.items():
        if value:
            message[key] = value
    message_slack(message)

def iam_sync(aws_creds, iam_groups, azure_utils, account):
    members = []
    for iam_group in iam_groups:
        members += azure_utils.get_AD_group_members(iam_groups[iam_group])

    ad_members = list(set(members))
    aws_members = aws_creds.get_all_iam_users()
    make_decision(aws_creds, ad_members, aws_members, account)



def sync_aws_ad():
    message = dict()
    result = dict()
    logger.debug(
        'Looking for AWS users to delete that do not exist or are not active in AD')
    global aws_accounts, azure_utils
    aws_accounts, azure_utils = construct_accounts_map()
    starttime = time.time()
    processes = []
    for account in aws_accounts:
        p = multiprocessing.Process(target=process_sync, args=(account,))
        processes.append(p)
        p.start()

    for process in processes:
        process.join()

    output = 'Processed {} accounts. That took {} seconds'.format(len(processes), time.time() - starttime)
    print(output)
    #Send result to slack
    result["Accounts Processed"] = len(processes)
    result["Time Taken"] = "{} seconds".format(int(float(time.time() - starttime)))
    message['Result'] = result
    message_slack(message)


def process_sync(account):
    all_ad_aws_groups = azure_utils.get_all_aws_groups(account)
    aws_creds = get_sts_iam_object(sts_client, aws_accounts[account], "iam", account)
    iam_sync(aws_creds, all_ad_aws_groups, azure_utils, account)


def set_log_level():
    if os.environ.get('DEBUG'):
        log_level = logging.DEBUG
        logging.getLogger('botocore').setLevel(log_level)
    else:
        logging.getLogger('botocore').setLevel(logging.ERROR)
        log_level = logging.INFO
    logger.setLevel(log_level)
    logging.basicConfig(
        level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.getLogger('requests').setLevel(log_level)


def main(extend=None, context=None):
    set_log_level()
    error_counter = 0

    try:
        print('Main Function Called')
        logger.debug('Trail')
        sync_aws_ad()
        error_counter = 0
    except Exception as error:
        logger.exception(error)
        # if we regularly have exceptions, let aws slack know about it once per day.
        error_counter += 1
        if error_counter % 48 == 4:
            slack_error = '```This exception is being sent to slack since it is the 4th one is a row. %s```' % error
            message_slack(slack_error)
        sys.exit(1)


if __name__ == "__main__":
    current = time.time()
    main()
    taken = time.time() - current
    print(taken)
