<?php

namespace AlibabaCloud\Credentials\Configure;

class Config
{
    const ENV_PREFIX = "{{env_prefix}}";
    const KEY = "{{user_agent_prefix}}";
    const STS_DEFAULT_ENDPOINT = "{{sts_default_endpoint}}";
    const ENDPOINT_SUFFIX = "{{endpoint_suffix}}";
    const CREDENTIAL_FILE_PATH = "{{credential_file_path}}";
    const CLI_CONFIG_DIR = "{{config_path}}";
    const ECS_METADATA_HOST = "{{metadata_host}}";
    const ECS_METADATA_HEADER_PREFIX = "{{imds_header_prefix}}";
    const SIGN_PREFIX = "{{sign_prefix}}";
    const SIGNATURE_TYPE_PREFIX = "{{signature_type_prefix}}";
}
