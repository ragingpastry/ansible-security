import os
import re

import testinfra.utils.ansible_runner
import lxml.html
from StringIO import StringIO

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_openscap_compliance(host):

    host.run("oscap xccdf eval "
             "--profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa "
             "--results scan-xccdf-centos7-stig-sida_after.xml "
             "--report /tmp/centos7-disa-stig-report_after.html "
             "--oval-results "
             "/usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml")

    html = host.file("/tmp/centos7-disa-stig-report_after.html").content_string
    html = lxml.html.parse(StringIO(html))
    oscap_results_preparsed = html.xpath('//*[@id="compliance-and-scoring"]/div[2]/div[2]/text()')
    oscap_results = oscap_results_preparsed[0].split(' ')[0]

    assert oscap_results <= '35'


def test_nessus_rhel_07_010030(host):
    """
    rhel-07-010300 - The OS must display the Standard Mandatory DoD Notice and Consent Banner before granting access
    """

    content = host.file('/etc/dconf/db/gdm.d/01-banner-message').content

    assert bool(re.search("[\s]*banner-message-enable[\s]*=[\s]*true[\s]*", content))


def test_nessus_rhel_07_010040(host):
    """
    rhel-07-010040 - The OS must display the approved Standard Mandatory DoD Notice and Consent Banner before granding access via GUI
    """

    content = host.file('/etc/dconf/db/local.d/01-banner-message').content

    assert bool(re.search("[\s]*banner-message-text[\s]*=[\s]*.WARNING.*[\s]*", content))


def test_nessus_rhel_07_010060(host):
    """
    rhel-07-010060 - The OS must enable a user session lock until that user re-establishes access using established ID and auth procedures
    """

    content = host.file('/etc/dconf/db/local.d/00-screensaver').content

    assert bool(re.search("[\s]*lock-enabled[\s]*=[\s]*true", content))


def test_nessus_rhel_07_010070(host):
    """
    rhel-07-010070 - The OS must initiate a screesaver after a 15-minute period of inactivity for graphical user interfaces
    """

    content = host.file('/etc/dconf/db/local.d/00-screensaver').content

    assert bool(re.search("[\s]*idle-delay[\s]*=[\s]*uint32[\s]*([1-9]|[1-8][0-9]|9[0-9]|[1-8][0-9]{2}|900)", content))


# def test_nessus_rhel_07_010080(host):
#    """
#    rhel-07-010080 - The OS must set the idle delay setting for all connection types
#    """
#
#    content = host.file('/etc/dconf/db/local.d/locks/')


def test_nessus_rhel_07_010050(host):
    """
    rhel-07-010050 - The OS must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access via CLI
    """

    banner_string = "^WARNING This is a RESTRICTED ACCESS"

    assert host.file("/etc/issue").contains(banner_string)


def test_nessus_rhel_07_010090(host):
    """
    rhel-07-010090 - The OS must have the screen package installed
    """

    assert host.package("screen").is_installed


def test_nessus_rhel_07_010119(host):
    """
    rhel-07-010119 - When passwords are changed or new passwords are established, pwquality must be used
    """

    pwquality_regex = "password   required     pam_pwquality.so"
    content = host.file('/etc/pam.d/passwd').content

    assert pwquality_regex in content


def test_nessus_rhel_07_010120_010190(host):
    """
    When passwords are changed or new passwords are established, the new password must contain
    at least 1 upper-case character
    rhel07-010120 = ucredit
    rhel07-010130 = lcredit
    rhel07-010140 = dcredit
    rhel07-010150 = ocredit
    rhel07-010160 = difok
    rhel07-010170 = minclass
    rhel07-010180 = maxrepeat
    rhel07-010190 = maxclassrepeat
    """

    content = host.file('/etc/security/pwquality.conf').content

    assert "ucredit = -1" in content
    assert "lcredit = -1" in content
    assert "dcredit = -1" in content
    assert "ocredit = -1" in content
    assert "difok = 8" in content
    assert "minclass = 4" in content
    assert "maxrepeat = 2" in content
    assert "maxclassrepeat = 4" in content


def test_nessus_rhel_07_010200(host):
    """
    rhel-07-010200 - The PAM service must be configured to store only encrypted representations of passwords
    """

    content = host.file('/etc/pam.d/system-auth-ac').content

    assert bool(re.search("password.*sufficient.*pam_unix.so.*sha512", content))


def test_nessus_rhel_07_010210(host):
    """
    rhel-07-010210 - The shadow file must be configured to store onyl encrypted representations of passwords
    """

    content = host.file('/etc/login.defs').content

    assert "ENCRYPT_METHOD SHA512" in content


def test_nessus_rhel_07_010220(host):
    """
    rhel-07-010220 - User and group account administration utilities must be configured to store only encrypted
    respresentations of passwords
    """

    content = host.file('/etc/libuser.conf').content

    assert bool(re.search("[\s]*crypt_style[\s]*=[\s]*sha512", content))


def test_nessus_rhel_07_010230_010250(host):
    """
    rhel-07-010230 - Passwords for new users must be restricted to a 24hours/1 day minimum lifetime
    rhel-07-010250 - Passwords for new users must be restricted to a 60-day maximum lifetime
    """

    content = host.file('/etc/login.defs').content

    assert bool(re.search("[\s]*PASS_MIN_DAYS[\s]*([1-9]|[1-9][0-9]+)", content))
    assert bool(re.search("[\s]*PASS_MAX_DAYS[\s]*([1-9]|[1-5][0-9]|60)", content))


def test_nessus_rhel_07_010270(host):
    """
    rhel-07-010270 - Passwords must be prohibited from reuse for a minimum of five generations
    """

    content = host.file('/etc/pam.d/system-auth-ac').content

    assert bool(re.search("[\s]*password[\s]*sufficient[\s].*remember[\s]*=[\s]*[1-5]", content))


def test_nessus_rhel_07_010280(host):
    """
    rhel-07-010280 - Passwords must be a minimum of 15 characters in length
    """

    content = host.file('/etc/security/pwquality.conf').content

    assert bool(re.search("[\s]*minlen[\s]*=[\s]*(1[5-9]|[2-9][0-9])", content))


def test_nessus_rhel_07_010290(host):
    """
    rhel-07-010290 - The system must not have accounts configured with blank or null passwords
    """

    content = host.file('/etc/pam.d/system-auth-ac').content

    assert not bool(re.search(".*nullok.*", content))


def test_nessus_rhel_07_010300(host):
    """
    rhel-07-010300 - The SSH daemon must not allow authentication using an empty password
    """

    content = host.file('/etc/ssh/sshd_config').content

    assert bool(re.search("[Pp]ermit[Ee]mpty[Pp]asswords[\s]*no", content))


def test_nessus_rhel_07_010310(host):
    """
    rhel-07-010310 - The OS must disable account identifiers (individuals, groups, roles, and devices)
    if the password expires
    """

    content = host.file('/etc/default/useradd').content

    assert bool(re.search("INACTIVE[\s]*=[\s]*0", content))


def test_nessus_rhel_07_010320_010330(host):
    """
    rhel-07-010320 - Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked
    """

    files = ['/etc/pam.d/system-auth-ac', '/etc/pam.d/password-auth-ac']
    for f in files:
        content = host.file(f).content
        assert bool(re.search(''.join((
            "auth[\s]*required[\s]*pam_faillock\.so[\s]*preauth[\s]*silent[\s]*audit[\s]*",
            "deny=3[\s]*even_deny_root[\s]*fail_interval=900[\s]*unlock_time=604800")), content))
        assert bool(re.search(''.join((
            "auth[\s]*\[default=die\][\s]*pam_faillock\.so[\s]*authfail[\s]*audit[\s]*",
            "deny=3[\s]*even_deny_root[\s]*fail_interval=900[\s]*unlock_time=604800")), content))
        assert bool(re.search("auth[\s]*sufficient[\s]*pam_unix\.so[\s]*try_first_pass", content))


def test_nessus_rhel_07_010430(host):
    """
    rhel-07-010430 - The delay between logon prompts following a failed console logon attempt must be at least four seconds
    """

    content = host.file('/etc/login.defs').content

    assert bool(re.search("[\s]*FAIL_DELAY[\s]*([4-9]|[1-9][0-9]+)", content))


def test_nessu_rhel_07_010460_010470(host):
    """
    rhel-07-010460 - The OS must not allow users to override SSH environment variables
    rhel-07-010470 - The OS must not allow a non-certificate trusted host SSH logon to the system
    """

    content = host.file('/etc/ssh/sshd_config').content

    assert bool(re.search("[^#][\s]*[Pp]ermit[Uu]ser[Ee]nvironment[\s]*no", content))
    assert bool(re.search("[^#][\s]*[Hh]ostbased[Aa]uthentication[\s]*no", content))


def test_nessus_rhel_07_020000_020010(host):
    """
    rhel-07-020000 - The rsh-server package must not be installed
    rhel-07-020010 - The ypserv package must not be installed
    """

    assert not host.package('rsh-server').is_installed
    assert not host.package('ypserv').is_installed


def test_nessus_rhel_07_020030_020040(host):
    """
    rhel-07-020030 - A file integrity tool must verify the baseline operating system configuration at least weekly - aide installed
    """

    root_crontab = host.run("/usr/bin/crontab -u root -l | /usr/bin/grep 'aide'")

    assert bool(re.search("[0-9,]+[\s]+[0-9,]+[\s]+\*[\s]+\*[\s]+\*[\s]+", root_crontab.stdout))
    assert bool(re.search("mail .+@.+", root_crontab.stdout))
    assert host.package('aide').is_installed


def test_nessus_rhel_07_020050_020060_020200(host):
    """
    rhel-07-020050-020060
    The OS must prevent the install of software, patches, service packs, device drivers, or OS components without verification
    rhel-07-020200 - The OS must remove all software components after updated versions have been installed
    """

    content = host.file('/etc/yum.conf').content

    assert bool(re.search("[\s]*gpgcheck[\s]*=[\s]*1[\s]*", content))
    assert bool(re.search("[\s]*localpkg_gpgcheck[\s]*=*[\s]*1[\s]*", content))
    assert bool(re.search("[\s]*clean_requirements_on_remove[\s]*=[\s]*", content))


def test_nessus_rhel_07_020100(host):
    """
    rhel-07-020100 - USB mass storage must be disabled
    """

    content = host.file('/etc/modprobe.d/blacklist.conf').content

    assert bool(re.search("[\s]*blacklist[\s]*usb-storage", content))


def test_nessus_rhel_07_020210_020220(host):
    """
    rhel-07-020210 - The OS must enable SELinux
    rhel-07-020220 - The OS must enable the SELinux targeted policy
    """

    content = host.file('/etc/selinux/config').content

    assert bool(re.search("[\s]*[sS][eE][lL][iI][nN][uU][xX][\s]*=[\s]*[eE][nN][fF][oO][rR][cC][iI][nN][gG][\s]*", content))
    assert bool(re.search("[\s]*[sS][eE][lL][iI][nN][uU][xX][tT][yY][pP][eE][\s]*=[\s]*[Tt][Aa][Rr][Gg][Ee][Tt][Ee][Dd][\s]*", content))


def test_nessus_rhel_07_020230(host):
    """
    rhel-07-020230 - The x86 Ctrl-Alt-Delete key sequence must be disabled - service
    """

    assert not host.service('ctrl-alt-del.service').is_enabled


def test_nessus_rhel_07_020600(host):
    """
    rhel-07-020600 - All local interactive user accounts, upon creation, must be assigned a home directory
    """

    content = host.file('/etc/login.defs').content

    assert bool(re.search("[\s]*CREATE_HOME[\\s]*yes", content))


def test_nessus_rhel_07_021100(host):
    """
    rhel-07-021100 - Cron logging must be implemented
    rhel-07-021100 - If the cron.allow file exists it must be owned by root
    """

    content = host.file('/etc/rsyslog.conf').content
    if host.file('/etc/cron.allow').exists:
        assert host.file('/etc/cron.allow').user == 'root'
        assert host.file('/etc/cron.allow').group == 'root'

    assert bool(re.search("[\s]*cron\.\*\s+/var/log/cron\s*", content))


def test_nessus_rhel_07_021300(host):
    """
    rhel-07-021300 - Kernel core dumps must be disabled unless needed
    """

    assert not host.service('kdump.service').is_enabled


def test_nessus_rhel_07_021320_0231340(host):
    """
    rhel-07-021320 - The system must use a separate file system for /var
    rhel-07-021330 - The system must use a separate file system for the system audit data path
    rhel-07-023140 - The system must use a separate file system for /tmp
    """

    content = host.file('/etc/fstab').content

    assert bool(re.search("[\s]*[^#]*[\s]+\/var[\s]", content))
    assert bool(re.search("[\s]*[^#]*[\s]+\/var\/log/audit[\s]", content))
    assert bool(re.search("\s]*[^#]*[\s]+\/tmp[\s]", content))


def test_nessus_rhel_07_021350(host):
    """
    rhel-07-021350 - The OS must implement NIST FIPS-validated cryptography
    """

    fips_enabled = host.run('/usr/bin/cat /proc/sys/crypto/fips_enabled')

    assert host.package('dracut-fips').is_installed
    assert fips_enabled.stdout == '1'


def test_nessus_rhel_07_021600(host):
    """
    rhel-07-021600 - The file integrity tool must be configured to verify Access Control Lists (ACLs)
    rhel-07-021610 - The file integrity tool must be configured to verify extended attributes
    rhel-07-021620 - The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating
                     file contents and directories
    """

    content = host.file('/etc/aide.conf').content

    assert bool(re.search("[\s]*EVERYTHING[\s]*=[\s]*.*(acl).*", content))
    assert bool(re.search("[\s]*EVERYTHING[\s]*=[\s]*.*(xattrs).*", content))
    assert bool(re.search("[\s]*EVERYTHING[\s]*=[\s]*.*(sha512).*", content))


def test_nessus_rhel_07_021700(host):
    """
    rhel-07-021700 - The system must not allow removable media to be used as the boot loader unless approved
    """

    alternate_grubs = host.run("/usr/bin/find / -name grub.cfg 2>/dev/null | /usr/bin/egrep -v '(/boot/grub2/grub.cfg|/boot/efi/EFI/redhat/grub.cfg)'")

    assert alternate_grubs.rc == 1


def test_nessus_rhel_07_021710(host):
    """
    rhel-07-021710 - The telnet-server package must not be installed
    """

    assert not host.package('telnet-server').is_installed


def test_nessus_rhel_07_030000(host):
    """
    rhel-07-030000 - Auditing must be configured to produce records containing sufficient information
    """

    assert host.service('auditd.service').is_running


def test_nessus_rhel_07_030300_030320(host):
    """
    rhel-07-030300 - The OS must off-load audit records onto a different system or media from the system being audited
    rhel-07-030310 - The OS must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited
    rhel-07-030320 - The audit system must take appropriate action when the audit storage volume is full"
    rhel-07-030321 - The audit system must take appropriate action when there is an error sending audit records to a remote system
    """

    content = host.file('/etc/audisp/audisp-remote.conf').content

    assert bool(re.search("[\s]*remote_server[\s]*=[\s]*loghost", content))
    assert bool(re.search("[\s]*enable_krb5[\s]*=[\s]*yes", content))
    assert bool(re.search("[\s]*disk_full_action[\s]*=[\s]*([Ss][Yy][Ss][Ll][Oo][Gg]|[Ss][Ii][Nn][Gg][Ll][Ee]|[Hh][Aa][Ll][Tt])", content))
    assert bool(re.search("[\s]*network_failure_action[\s]*=[\s]*([Ss][Yy][Ss][Ll][Oo][Gg]|[Ss][Ii][Nn][Gg][Ll][Ee]|[Hh][Aa][Ll][Tt])", content))


def test_nessus_rhel_07_030330_030350(host):
    """
    rhel-07-030330 - The OS must immediately notify the SA and ISSO when allocated audit record storage volume reaches 75%"
    rhel-07-030340 - The OS must immediately notify the SA and ISSO via email when the threshold for the max audit storage capacity is reached
    rhel-07-030350 - The OS must immediately notify the SA and ISSO when the threshold for the repo max audit record storage capacity is reached
    """

    content = host.file('/etc/audit/auditd.conf').content

    assert bool(re.search("[\s]*space_left[\s]*=[\s]*75", content))
    assert bool(re.search("[\s]*space_left_action[\s]*=[\s]*email", content))
    assert bool(re.search("[\s]*action_mail_acct[\s]*=[\s]*root", content))


def test_nessus_rhel_07_030370_030400(host):
    """
    rhel-07-030370 - All uses of the chown command must be audited -64 bit
    rhel-07-030380 - All uses of the fchown comand must be audited - 64bit
    rhel-07-030390 - All uses of the lcown command must be audited - 64bit
    rhel-07-030400 - All uses of the fchownat command must be audited - 64bit
    rhel-07-030410 - All uses of the chmod command must be audited - 64bit
    rhel-07-030420 - All uses of the fchmod command must be audited - 64bit
    rhel-07-030430 - All uses of the fchmodat command must be audited - 64bit
    rhel-07-030440 - All uses of the setxattr command must be audited - 64bit
    rhel-07-030450 - All uses of the fsetxattr command must be audited - 64bit
    rhel-07-030460 - All uses of the lsetxattr command must be audited - 64bit
    rhel-07-030470 - All uses of the removexattr command must be audited - 64bit
    rhel-07-030480 - All uses of the fremovexattr command must be audited - 64bit
    rhel-07-030490 - All uses of the lremovexattr command must be audited - 64bit
    rhel-07-030500 - All uses of the creat command must be audited - 64bit
    rhel-07-030510 - All uses of the open command must be audited - 64bit
    rhel-07-030520 - All uses of the openat command must be audited - 64bit
    rhel-07-030530 - All uses of the open_by_handle_at command must be audited - 64 bit
    rhel-07-030540 - All uses of the truncate command must be audited - 64bit
    rhel-07-030550 - All uses of the ftruncate command must be audited - 64bit
    rhel-07-030740 - All uses of the mount command must be audited - 64bit
    rhel-07-030820 - All uses of the init_module command must be audited - 64bit
    rhel-07-030830 - ALl uses of the delete_module command must be audited - 64bit
    rhel-07-030880 - All uses of the rename command must be audited - 64bit
    rhel-07-030890 - All uses of the renameat command must be audited - 64bit
    rhel-07-030900 - All uses of the rmdir command must be audited - 64bit
    rhel-07-030910 - All uses of the unlink command must be audited - 64bit
    rhel-07-030920 - All uses of the unlinkat command must be audited - 64bit
    rhel-07-030560 - All uses of the semanage command must be audited
    rhel-07-030570 - All uses of the setsebool command must be audited
    rhel-07-030580 - All uses of the chcon command must be audited
    rhel-07-030590 - All uses of the restorecon command must be audited
    rhel-07-030600 - The OS must generate audit records for all successful/unsuccessful account access count events
    rhel-07-030610 - The OS must generate audit records for all unsuccessful account access events
    rhel-07-030620 - The OS must generate audit records for all successful account access events
    rhel-07-030630 - All uses of the passwd command must be audited
    rhel-07-030640 - All uses of the unix_chkpwd command must be audited
    rhel-07-030650 - All uses of the gpasswd command must be audited
    rhel-07-030660 - All uses of the chage command must be audited
    rhel-07-030680 - All uses of the su command must be audited
    rhel-07-030690 - All uses of the sudo command must be audited
    rhel-07-030700 - All uses of the sudoers command must be audited - sudoers
    rhel-07-030710 - All uses of the newgrp command must be audited
    rhel-07-030720 - All uses of the chsh command must be audited
    rhel-07-030730 - All uses of the sudoedit command must be audited
    rhel-07-030750 - All uses of the umount command must be audited
    rhel-07-030760 - All uses of the postdrop command must be audited
    rhel-07-030770 - All uses of the postqueue command must be audited
    rhel-07-030780 - All uses of the ssh-keysign command must be audited
    rhel-07-030800 - All uses of the crontab command must be audited
    rhel-07-030810 - All uses of the pam_timestamp_check command must be audited
    rhel-07-030840 - All uses of the insmod command must be audited
    rhel-07-030850 - All uses of the rmmod command must be audited
    rhel-07-030860 - All uses of the modprobe command must be audited
    rhel-07-030870 - The OS must generate auti records for all creations, modifications, disabling, and termination events for /etc/passwd
    rhel-07-030871 - The OS must generate audit records for all creations, modifications, disabling, and terminiation events for /etc/group
    rhel-07-030872 - The OS must generate audit records for all creations, modifications, disabling, and termination events for /etc/gshadow
    rhel-07-030873 - The OS must generate audit records for all creations, modifications, disabling, and termination events for /etc/shadow
    rhel-07-030874 - The OS must generate audit records for all creations, modifications, disabling, and termination events for /etc/opasswd
    """

    content = host.file('/etc/audit/rules.d/audit.rules').content

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+chown[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+fchown[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+lchown[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+fchownat[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+chmod[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+fchmod[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+fchmodat[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+setxattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+fsetxattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+lsetxattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+removexattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+fremovexattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+lremovexattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+chown[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+fchown[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+lchown[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+fchownat[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+chmod[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+fchmod[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+fchmodat[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+setxattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+fsetxattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+lsetxattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+removexattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+fremovexattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+lremovexattr[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+perm_mod")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+creat[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+open[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+openat[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+open_by_handle_at[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+truncate[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+ftruncate[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+creat[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+open[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+openat[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+open_by_handle_at[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+truncate[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+ftruncate[\s]+",
        "-F[\s]+exit=-EACCES[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+access")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+mount[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-mount")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+mount[\s]+",
        "-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-mount")), content))

    assert bool(re.search("[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+init_module[\s]+-k[\s]+module-change", content))
    assert bool(re.search("[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+delete_module[\s]+-k[\s]+module-change", content))

    assert bool(re.search("[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+init_module[\s]+-k[\s]+module-change", content))
    assert bool(re.search("[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+delete_module[\s]+-k[\s]+module-change", content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+",
        "rename[\s]+-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+",
        "renameat[\s]+-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+",
        "rmdir[\s]+-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+",
        "unlink[\s]+-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b64[\s]+-S[\s]+",
        "unlinkat[\s]+-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+rename[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+renameat[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+rmdir[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+unlink[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=b32[\s]+-S[\s]+unlinkat[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+delete")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/sbin/semanage[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/sbin/setsebool[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/chcon[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/sbin/restorecon[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))

    assert bool(re.search("[\s]*-w[\s]+/var/log/tallylog[\s]+-p[\s]+wa[\s]+-k[\s]+logins", content))
    assert bool(re.search("[\s]*-w[\s]+/var/run/faillock/[\s]+-p[\s]+wa[\s]+-k[\s]+logins", content))
    assert bool(re.search("[\s]*-w[\s]+/var/log/lastlog[\s]+-p[\s]+wa[\s]+-k[\s]+logins", content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/passwd[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-passwd")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/sbin/unix_chkpwd[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-passwd")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/gpasswd[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-passwd")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/gpasswd[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-passwd")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/sbin/userhelper[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-passwd")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/bin/su[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/sudo[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search("[\s]*-w[\s]+/etc/sudoers[\s]+-p[\s]+wa[\s]+-k[\s]+privileged-actions", content))
    assert bool(re.search("[\s]*-w[\s]+/etc/sudoers\.d[\s]+-p[\s]+wa[\s]+-k[\s]+privileged-actions", content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/newgrp[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/chsh[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/bin/sudoedit[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-priv_change")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/bin/umount[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-mount")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/sbin/postdrop[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-postfix")), content))
    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/sbin/postqueue[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-postfix")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/libexec/openssh/ssh-keysign[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-ssh")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/usr/bin/crontab[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-cron")), content))

    assert bool(re.search(''.join((
        "[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=/sbin/pam_timestamp_check[\s]+",
        "-F[\s]+perm=x[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+privileged-pam")), content))

    assert bool(re.search("[\s]*-w[\s]+/sbin/insmod[\s]+-p[\s]+x[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+module-change", content))
    assert bool(re.search("[\s]*-w[\s]+/sbin/rmmod[\s]+-p[\s]+x[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+module-change", content))
    assert bool(re.search("[\s]*-w[\s]+/sbin/modprobe[\s]+-p[\s]+x[\s]+-F[\s]+auid!=4294967295[\s]+-k[\s]+module-change", content))

    assert bool(re.search("[\s]*-w[\s]+/etc/passwd[\s]+-p[\s]+wa[\s]+-k[\s]+identity", content))
    assert bool(re.search("[\s]*-w[\s]+/etc/group[\s]+-p[\s]+wa[\s]+-k[\s]+identity", content))
    assert bool(re.search("[\s]*-w[\s]+/etc/gshadow[\s]+-p[\s]+wa[\s]+-k[\s]+identity", content))
    assert bool(re.search("[\s]*-w[\s]+/etc/shadow[\s]+-p[\s]+wa[\s]+-k[\s]+identity", content))
    assert bool(re.search("[\s]*-w[\s]+/etc/security/opasswd[\s]+-p[\s]+wa[\s]+-k[\s]+identity", content))


def test_nessus_rhel_07_031000_031010(host):
    """
    rhel-07-031000 - The system must send rsyslog output to a log aggregation server
    rhel-07-031010 - The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation
    """

    content = host.file('/etc/rsyslog.conf').content

    assert bool(re.search("[\s]*\*\.\*[\s]+(@|@@|:omrelp:)loghost[\\s]*", content))
    assert bool(re.search("[\s]*[Mm]od[Ll]oad[\s]*imtcp", content))


def test_nessus_rhel_07_040000(host):
    """
    rhel-07-040000 - The OS must limit the number of concurrent sessions to 10 for all accounts and/or account types
    """

    content = host.file('/etc/security/limits.conf').content

    assert bool(re.search("[\s]*\\*[\s]+hard[\s]+maxlogins[\s]+([1-9]|10)[\s]*", content))


def test_nessus_rhel_07_040110(host):
    """
    rhel-07-040110 - A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications
    """

    content = host.file('/etc/ssh/sshd_config').content

    assert bool(re.search("[\s]*Ciphers[\s]+(,?aes128-ctr|,?aes192-ctr|,?aes256-ctr){3}[\s]*", content))


def test_nessus_rhel_07_040300(host):
    """
    rhel-07-040300 - All networked systems must have SSH installed - openssh-clients
    """

    assert host.package('openssh-clients').is_installed
    assert host.package('openssh-server').is_installed


def test_nessus_rhel_07_040310(host):
    """
    rhel-07-040310 - All networked systems must use SSH for confidentiality and integrity of transmitted and received information
    """

    assert host.service('sshd').is_running


def test_nessus_rhel_07_040320_040470(host):
    """
    rhel-07-040320 - All connections associated with SSH must terminate at the end of the session or after 10 minutes of inactivity
    rhel-07-040330 - The SSH daemon must not allow authentication using RSA rhosts authentication
    rhel-07-040340 - All network connections associated with SSH traffic must terminate after a period of inactivity
    rhel-07-040350 - The SSH daemon must not allow authentication using rhosts authentication
    rhel-07-040360 - The system must display date and time of the last successful account logon upon an SSH logon - PrintLastLog
    rhel-07-040370 - The system must not permit direct logons to the root account using remote access via SSH
    rhel-07-040380 - The SSH daemon must not allow authentication using known hosts authentication
    rhel-07-040390 - The SSH daemon must be configured to only use the SSHv2 protocol
    rhel-07-040400 - The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved algorithms
    rhel-07-040430 - The SSH daemon must not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed
    rhel-07-040440 - The SSH daemon must not permit Kerberos authentication unless needed
    rhel-07-040450 - The SSH daemon must perform strict mode checking of home directory configuration files
    rhel-07-040460 - The SSH daemon must use privilege separation
    rhel-07-040470 - The SSH daemon must not allow compresssion or must only allow compression after successful authentication
    """

    content = host.file('/etc/ssh/sshd_config').content

    assert bool(re.search("[\s]*ClientAliveInterval[\s]+([1-9]|[1-8][0-9]|9[0-9]|[1-5][0-9]{2}|600)[\s]*", content))
    assert bool(re.search("[\s]*RhostsRSAAuthentication[\s]+[Nn][Oo]", content))
    assert bool(re.search("[\s]*ClientAliveCountMax[\s]+0[\s]*", content))
    assert bool(re.search("[\s]*IgnoreRhosts[\s]+yes[\s]*", content))
    assert bool(re.search("[\s]*PrintLastLog[\s]+[Yy][Ee][Ss][\s]*", content))
    assert bool(re.search("[\s]*PermitRootLogin[\s]+no[\s]*", content))
    assert bool(re.search("[\s]*IgnoreUserKnownHosts[\s]+[Yy][Ee][Ss][\s]*", content))
    assert bool(re.search("[\s]*Protocol[\s]+2[\s]*", content))
    assert bool(re.search("[\s]*MACs[\s]*(,?hmac-sha2-256|,?hmac-sha2-512){1,2}", content))
    assert bool(re.search("[\s]*GSSAPIAuthentication[\s]+[nN][oO][\s]*", content))
    assert bool(re.search("[\s]*KerberosAuthentication[\s]+[nN][oO]\s*", content))
    assert bool(re.search("[\s]*StrictModes[\s]+[yY][eE][sS][\s]*", content))
    assert bool(re.search("[\s]*UsePrivilegeSeparation[\s]+(sandbox|yes)", content))
    assert bool(re.search("[\s]*Compression[\s]+([nN][oO]|[dD][eE][lL][aA][yY][eE][dD])\s*", content))


def test_nessus_rhel_07_040410(host):
    """
    rhel-07-040410 - The SSH public host key files must have mode 0644 or less permissive
    """

    ssh_host_key_pub_files = host.run('ls /etc/ssh/*key.pub').stdout

    for ssh_key_pub in ssh_host_key_pub_files.split('\n'):
        assert host.file(ssh_key_pub).mode == 0o644


def test_nessus_rhel_07_040420(host):
    """
    rhel-07-040420 - The SSH private host key files must have mode 06000 or less permissive
    """

    ssh_host_key_priv_files = host.run('ls /etc/ssh/*key').stdout

    for ssh_key in ssh_host_key_priv_files.split('\n'):
        assert host.file(ssh_key).mode == 0o600


def test_nessus_rhel_07_040500(host):
    """
    rhel-07-040500 - The OS must synchronize clocks with a server that is synchronized
    to one of the redundant time servers
    """

    assert host.service('chronyd').is_running


def test_nessus_rhel_07_040520(host):
    """
    rhel-07-040520 - The OS must enable an application firewall, if available
    """

    assert host.service('firewalld').is_running


def test_nessus_rhel_07_040530(host):
    """
    rhel-07-040530 - The system must display the date and time of the last successful account logon up logon
    """

    content = host.file('/etc/pam.d/postlogin-ac').content

    assert bool(re.search("[\s]*session[\s]+required[\s]+pam_lastlog\.so[\s]+showfailed", content))


def test_nessus_rhel_07_040610(host):
    """
    rhel-07-040610 - The system must not forward
        Internet Protocol version 4 (IPv4) source-routed packets
    rhel-07-040620 - The system must not forward
        Internet Protocol version 4 (IPv4) source-routed packets by default
    rhel-07-040630 - The system must not respond to
        Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echos.
    rhel-07-040640 - The system must prevent
        Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages
    rhel-07-040641 - The system must ignore
        Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages
    rhel-07-040650 - The system must not allow interfaces to perform
        Internet Protocol version 4 (IPv4) ICMP redirects by default
    rhel-07-040660 - The system must not send Internet Protocol version 4 (IPv4)
        Internet Control Message Protocol (ICMP) redirects
    rhel-07-040740 - The system must not be performing
        packet forwarding unless the system is a router
    rhel-07-040830 - The system must no forward IPv6 source-routed packets
    """

    sysctl_commands = [
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.conf.all.accept_source_route'":
            "[\s]*net\.ipv4\.conf\.all\.accept_source_route[\s]*=[\s]*0"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.conf.default.accept_source_route'":
            "[\s]*net\.ipv4\.conf\.default\.accept_source_route[\s]*=[\s]*0"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.icmp_echo_ignore_broadcasts'":
            "[\s]*net\.ipv4\.icmp_echo_ignore_broadcasts[\s]*=[\s]*1"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.conf.default.accept_redirects'":
            "[\s]*net\.ipv4\.conf\.default\.accept_redirects[\s]*=[\s]*0"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.conf.all.accept_redirects'":
            "[\s]*net\.ipv4\.conf\.all\.accept_redirects[\s]*=[\s]*0"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.conf.default.send_redirects'":
            "[\s]*net\.ipv4\.conf\.default\.send_redirects[\s]*=[\s]*0"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.conf.all.send_redirects'":
            "[\s]*net\.ipv4\.conf\.all\.send_redirects[\s]*=[\s]*0"},
        {"/usr/sbin/sysctl -a | /usr/bin/grep 'net.ipv4.ip_forward '":
            "^[\s]*net\.ipv4\.ip_forward[\s]*=[\s]*0"}
        ]

    for command in sysctl_commands:
        for k, v in command.items():
            output = host.run(k).stdout
            assert bool(re.search(v, output))


def test_nessus_rhel_07_040680(host):
    """
    rhel-07-040680 - The system must be configured to prevent unrestricted mail relaying
    """

    content = host.file('/etc/postfix/main.cf').content

    assert bool(re.search(''.join((
        '[\s]*smtpd_client_restrictions[\s]*=',
        '(.*permit.*reject|.*permit)')), content))


def test_nessus_rhel_07_040700(host):
    """
    rhel-07-040700 - The Trivial File Transfer Protocol (TFTP) server package
    must not be installed if not required for operational support
    """

    assert not host.package('tftp-server').is_installed


def test_nessus_rhel_07_041001(host):
    """
    rhel-07-041001 - The OS must have the required packages for multifactor authentication installed
    """

    packages = ['esc', 'pam_pkcs11', 'authconfig-gtk']

    for package in packages:
        assert host.package(package).is_installed
