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


def test_nessus_rhel_07_010050(host):
    """
    Checks that the banner message is enabled
    """

    banner_string = "^WARNING This is a RESTRICTED ACCESS"

    assert host.file("/etc/issue").contains(banner_string)


def test_nessus_rhel_07_010090(host):
    """
    Checks that the screen package is installed
    """

    assert host.package("screen").is_installed


def test_nessus_rhel_07_010119(host):
    """
    When passwords are changed or new passwords are established, pwquality must be used
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
    The PAM service must be configured to store only encrypted representations of passwords
    """

    content = host.file('/etc/pam.d/system-auth-ac').content

    assert bool(re.search("password.*sufficient.*pam_unix.so.*sha512", content))


def test_nessus_rhel_07_010210(host):
    """
    The shadow file must be configured to store onyl encrypted representations of passwords
    """

    content = host.file('/etc/login.defs').content

    assert "ENCRYPT_METHOD SHA512" in content

def test_nessus_rhel_07_010220(host):
    """
    User and group account administration utilities must be configured to store only encrypted
    respresentations of passwords
    """

    content = host.file('/etc/libuser.conf').content

    assert bool(re.search("[\s]*crypt_style[\s]*=[\s]*sha512", content))

def test_nessus_rhel_07_010230_010250(host):
    """
    Passwords for new users must be restricted to a 24hours/1 day minimum lifetime
    """

    content = host.file('/etc/login.defs').content

    assert bool(re.search("[\s]*PASS_MIN_DAYS[\s]*([1-9]|[1-9][0-9]+)", content))
    assert bool(re.search("[\s]*PASS_MAX_DAYS[\s]*([1-9]|[1-5][0-9]|60)", content))

def test_nessus_rhel_07_010270(host):
    """
    Passwords must be prohibited from reuse for a minimum of five generations
    """

    content = host.file('/etc/pam.d/system-auth-ac').content

    assert bool(re.search("[\s]*password[\s]*sufficient[\s].*remember[\s]*=[\s]*[1-5]", content))

def test_nessus_rhel_07_010280(host):
    """
    Passwords must be a minimum of 15 characters in length
    """

    content = host.file('/etc/security/pwquality.conf').content

    assert bool(re.search("[\s]*minlen[\s]*=[\s]*(1[5-9]|[2-9][0-9])", content))

def test_nessus_rhel_07_010290(host):
    """
    The system must not have accounts configured with blank or null passwords
    """

    content = host.file('/etc/pam.d/system-auth-ac').content

    assert bool(re.search(".*nullok.*", content)) == False

def test_nessus_rhel_07_010300(host):
    """
    The SSH daemon must not allow authentication using an empty password
    """

    content = host.file('/etc/ssh/sshd_config').content

    assert bool(re.search("[Pp]ermit[Ee]mpty[Pp]asswords[\s]*no", content))

def test_nessus_rhel_07_010310(host):
    """
    The OS must disable account identifiers (individuals, groups, roles, and devices)
    if the password expires
    """

    content = host.file('/etc/default/useradd').content

    assert bool(re.search("INACTIVE[\s]*=[\s]*0", content))

def test_nessus_rhel_07_010320_010330(host):
    """
    Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked
    """

    files = ['/etc/pam.d/system-auth-ac', '/etc/pam.d/password-auth-ac']
    for f in files:
      content = host.file(f).content
      assert bool(re.search("auth[\s]*required[\s]*pam_faillock\.so[\s]*preauth[\s]*silent[\s]*audit[\s]*deny=3[\s]*even_deny_root[\s]*fail_interval=900[\s]*unlock_time=604800", content))
      assert bool(re.search("auth[\s]*\[default=die\][\s]*pam_faillock\.so[\s]*authfail[\s]*audit[\s]*deny=3[\s]*even_deny_root[\s]*fail_interval=900[\s]*unlock_time=604800", content))
      assert bool(re.search("auth[\s]*sufficient[\s]*pam_unix\.so[\s]*try_first_pass", content))

def test_nessus_rhel_07_010430(host):
    """
    The delay between logon prompts following a failed console logon attempt must be at least four seconds
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

    assert host.package('rsh-server').is_installed == False
    assert host.package('ypserv').is_installed == False

def test_nessus_rhel_07_020030_020040(host):
    """
    A file integrity tool must verify the baseline operating system configuration at least weekly - aide installed
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

    assert host.service('ctrl-alt-del.service').is_enabled == False


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

    assert host.service('kdump.service').is_enabled == False


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

    assert host.package('telnet-server').is_installed == False

def test_nessus_rhel_07_030000(host):
    """
    rhel-07-030000 - Auditing must be configured to produce records containing sufficient information
    """

    assert host.service('auditd.service').is_running


def test_nessus_rhel_07_030300(host):
    """
    rhel-07-030300 - The OS must off-load audit records onto a different system or media from the system being audited
    rhel_07_030310 - The OS must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited
    """

    content = host.file('/etc/audisp/audisp-remote.conf').content

    assert bool(re.search("[\s]*remote_server[\s]*=[\s]*loghost", content))
    assert bool(re.search("[\s]*enable_krb5[\s]*=[\s]*yes", content))
