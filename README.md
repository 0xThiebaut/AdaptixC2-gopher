# AdaptixC2 gopher agent extractor
Uses brute force to locate the configuration within an AdaptixC2's gopher agent.

## YARA
Is it an AdaptixC2's gopher agent? This YARA rule will tell if it looks like it.
```yara
rule adaptixc2_gopher {
    meta:
        description     = "Detects the Go field tags linked to the AdaptixC2 Gopher agent's protocol"
        author          = "Maxime THIEBAUT"
        date            = "2025-11-14"
        target_entity   = "file"

    strings:
        $msgpack_acp            = "msgpack:\"acp\""             ascii
        $msgpack_address        = "msgpack:\"address\""         ascii
        $msgpack_addresses      = "msgpack:\"addresses\""       ascii
        $msgpack_alive          = "msgpack:\"alive\""           ascii
        $msgpack_args           = "msgpack:\"args\""            ascii
        $msgpack_argspack       = "msgpack:\"argspack\""        ascii
        $msgpack_banner_size    = "msgpack:\"banner_size\""     ascii
        $msgpack_ca_cert        = "msgpack:\"ca_cert\""         ascii
        $msgpack_canceled       = "msgpack:\"canceled\""        ascii
        $msgpack_channel_id     = "msgpack:\"channel_id\""      ascii
        $msgpack_code           = "msgpack:\"code\""            ascii
        $msgpack_command_id     = "msgpack:\"command_id\""      ascii
        $msgpack_conn_count     = "msgpack:\"conn_count\""      ascii
        $msgpack_conn_timeout   = "msgpack:\"conn_timeout\""    ascii
        $msgpack_content        = "msgpack:\"content\""         ascii
        $msgpack_context        = "msgpack:\"context\""         ascii
        $msgpack_data           = "msgpack:\"data\""            ascii
        $msgpack_date           = "msgpack:\"date\""            ascii
        $msgpack_dst            = "msgpack:\"dst\""             ascii
        $msgpack_elevated       = "msgpack:\"elevated\""        ascii
        $msgpack_encrypt_key    = "msgpack:\"encrypt_key\""     ascii
        $msgpack_error          = "msgpack:\"error\""           ascii
        $msgpack_filename       = "msgpack:\"filename\""        ascii
        $msgpack_files          = "msgpack:\"files\""           ascii
        $msgpack_finish         = "msgpack:\"finish\""          ascii
        $msgpack_group          = "msgpack:\"group\""           ascii
        $msgpack_height         = "msgpack:\"height\""          ascii
        $msgpack_host           = "msgpack:\"host\""            ascii
        $msgpack_id             = "msgpack:\"id\""              ascii
        $msgpack_ipaddr         = "msgpack:\"ipaddr\""          ascii
        $msgpack_is_dir         = "msgpack:\"is_dir\""          ascii
        $msgpack_iv             = "msgpack:\"iv\""              ascii
        $msgpack_job_id         = "msgpack:\"job_id\""          ascii
        $msgpack_job_type       = "msgpack:\"job_type\""        ascii
        $msgpack_key            = "msgpack:\"key\""             ascii
        $msgpack_list           = "msgpack:\"list\""            ascii
        $msgpack_mode           = "msgpack:\"mode\""            ascii
        $msgpack_msgs           = "msgpack:\"msgs\""            ascii
        $msgpack_nlink          = "msgpack:\"nlink\""           ascii
        $msgpack_object         = "msgpack:\"object\""          ascii
        $msgpack_oem            = "msgpack:\"oem\""             ascii
        $msgpack_os             = "msgpack:\"os\""              ascii
        $msgpack_os_version     = "msgpack:\"os_version\""      ascii
        $msgpack_output         = "msgpack:\"output\""          ascii
        $msgpack_path           = "msgpack:\"path\""            ascii
        $msgpack_pid            = "msgpack:\"pid\""             ascii
        $msgpack_ppid           = "msgpack:\"ppid\""            ascii
        $msgpack_process        = "msgpack:\"process\""         ascii
        $msgpack_processes      = "msgpack:\"processes\""       ascii
        $msgpack_program        = "msgpack:\"program\""         ascii
        $msgpack_proto          = "msgpack:\"proto\""           ascii
        $msgpack_result         = "msgpack:\"result\""          ascii
        $msgpack_screens        = "msgpack:\"screens\""         ascii
        $msgpack_size           = "msgpack:\"size\""            ascii
        $msgpack_src            = "msgpack:\"src\""             ascii
        $msgpack_ssl_cert       = "msgpack:\"ssl_cert\""        ascii
        $msgpack_ssl_key        = "msgpack:\"ssl_key\""         ascii
        $msgpack_start          = "msgpack:\"start\""           ascii
        $msgpack_status         = "msgpack:\"status\""          ascii
        $msgpack_stderr         = "msgpack:\"stderr\""          ascii
        $msgpack_stdout         = "msgpack:\"stdout\""          ascii
        $msgpack_task           = "msgpack:\"task\""            ascii
        $msgpack_term_id        = "msgpack:\"term_id\""         ascii
        $msgpack_tty            = "msgpack:\"tty\""             ascii
        $msgpack_type           = "msgpack:\"type\""            ascii
        $msgpack_use_ssl        = "msgpack:\"use_ssl\""         ascii
        $msgpack_user           = "msgpack:\"user\""            ascii
        $msgpack_width          = "msgpack:\"width\""           ascii

    condition:
        30 of them
}
```