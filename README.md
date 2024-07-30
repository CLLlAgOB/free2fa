# Free2FA: Telegram bot for two-factor authentication

[![Docker Hub](https://img.shields.io/docker/pulls/clllagob/free2fa.svg?style=flat-square)][Docker Hub]
[![License](https://img.shields.io/github/license/clllagob/free2fa.svg?style=flat-square)][License]
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/5b38ed1f5983438693f7ab92724d1282)][Codacy Badge]
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=CLLlAgOB_free2fa&metric=security_rating)][Security Rating]

[Docker Hub]:           https://hub.docker.com/r/clllagob/free2fa
[License]:              https://github.com/clllagob/free2fa/blob/master/LICENSE
[Codacy Badge]:         https://app.codacy.com/gh/CLLlAgOB/free2fa/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade
[Security Rating]:  https://sonarcloud.io/summary/new_code?id=CLLlAgOB_free2fa

![screenshot](img/1-0en.png)  

Free2FA - This is a free solution that allows you to enable two-factor authentication for users
in a domain for various applications running with a RADIUS client. A Telegram bot is used to
implement the second factor authentication, which adds another layer of protection.  
[Версия на русском](./READMERU.md) 

## Main Components

- **Free2FA**: Handles authentication requests using Telegram bot.
- **FreeRADIUS**: The free2fa system uses FreeRADIUS to verify the user's login and password. If
the verification is successful, the authentication process proceeds to the next step, the second
security factor, which is handled by free2FA(In free2FA we do not pass the user's passwords only
the login). This component includes a FreeRADIUS server that processes RADIUS requests from the
client and passes them to free2fa_api for processing the second factor of the authentication.
- **SSSD**: (System Security Services Daemon) To integrate with an AD domain.

FreeRADIUS and SSSD is a free software, and is distributed under [GNU General Public License
version 3 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.en.html).  
The official website for FreeRADIUS is: [https://freeradius.org/](https://freeradius.org/)  
The official website for SSSD is: [https://sssd.io/](https://sssd.io/)  
We use FreeRADIUS and SSSD with no changes to the source code, only with configuration tweaks to
meet the requirements of our project.

## Free2FA Microservices

Free2FA consists of several microservices, each of which fulfills a specific role within the
two-factor authentication system:

### 1. free2fa_setup
The service is responsible for the initial setup and pre-configuration of the system. It includes
the generation and management of certificates required for the secure operation of other
components of the system.

### 2. free2fa_admin_html
The service provides a web interface for administrative management of the system.

### 3. free2fa_admin_api
API service for the administrative interface that provides interaction between the web interface
and the server side of the system.

### 4. free2fa_api
The main API service that handles authentication requests and interacts with the Telegram bot to
confirm user logins.

### Domain Integration

SSSD (System Security Services Daemon) is used to integrate the Linux machine into the domain and
manage credentials, which is in line with modern security requirements. SSSD provides support for
authentication via Kerberos, which is the standard for secure credential exchange on networked
systems. Using Kerberos in conjunction with SSSD ensures reliable and secure handling of user
accounts in the domain, providing centralized access control and authentication.

### Compatibility and installation requirements

The installation script was successfully tested on Ubuntu Server 22.04 LTS operating system.

**Installation description:**

1. Free2FA and its components are distributed as Docker containers. Only control ports are opened
for external access on the host: 443 for Admin and 5000 for API, both are secured using SSL
encryption.

2. FreeRADIUS and SSSD are installed automatically on the host machine via a script, and the other
components are installed in the Docker container automatically.

#### Authentication system workflow using the Cisco AnyConnect VPN server as an example

This process demonstrates how a two-factor authentication system using Free2FA and FreeRADIUS
integrates with external services, such as the Cisco AnyConnect VPN server, to provide enhanced
security for user access.

1. **Entering credentials:** The user starts the Cisco AnyConnect client and enters their domain
username and password.

2. **Referral Request:** The Cisco AnyConnect VPN server forwards the user's credentials to the
FreeRADIUS server for verification.

3. **First Factor Verification:** FreeRADIUS analyzes the login and password received. If the data
is correct, the server forwards the request to the second authentication factor in the Free2FA
system, passing it only the user's login.

4. **Processing of the second factor:** Free2FA checks the login against the database. Depending on
the security settings for that user, the system may send a request to confirm the login to the
user's Telegram application, skip the request without further confirmation, or block access.

5. **Access Confirmation:** The user receives a Telegram notification and confirms the login
request, then successfully connects to the VPN.

This mechanism confirms how universally and reliably two-factor authentication via Telegram bot can
be integrated into corporate security systems. Thanks to this, it is possible to adapt the method
to a variety of services that use RADIUS for authentication. This provides a wide range of
opportunities to strengthen the protection of access to various resources, making the process not
only secure, but also convenient for users.

## Installation

### Preparing the server

1. Create a new Telegram bot: https://core.telegram.org/bots#creating-a-new-bot.
2. You need to prepare a server based on Ubuntu Server 22.04 LTS in a minimal configuration,
providing network and DNS configuration. The server should have a minimum of 1 core processor and
1024 MB of RAM, although resource requirements may increase depending on load.
3. Create a directory for Free2FA settings:

   ```
   mkdir -p /opt/2fa/ && cd /opt/2fa/
   ```
4. Run the installation script:
   ```
   curl -o install.sh https://raw.githubusercontent.com/CLLlAgOB/free2fa/main/install.sh && bash install.sh
   ```
5. Follow the instructions in the script.
6. Create a dns entry for the admin portal (https://free2fa_admin_html by default) or the name you
specified in the ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML parameter.
The default password and login for the admin portal is: admin admin.

### Configuring the RADIUS client

1. Set the timeout higher than FREE2FA_TIMEOUT by 3 seconds.
2. Disable password management if there is such an option
(This implementation does not support CHAPv2).

### Debugging

You can use the following commands to manage the free2fa service:
- To stop the free2fa service, type: service free2fa stop
- To start the free2fa service, type: service free2fa start  

To view the Docker logs following the installation directory, use the command:  
docker-compose logs -f  
To access the FreeRADIUS logs, run the following command:  
cat /var/log/freeradius/radius.log  
To start FreeRADIUS in debug mode, first stop the FreeRADIUS service by running:  
service freeradius stop  
Then, to start FreeRADIUS in debug mode, execute:  
freeradius -Xx  

### Free2fa configuration parameters

- `CA_EXPIRY_DAYS`: Certificate validity, days.
- `FREE2FA_TELEGRAM_BOT_TOKEN`: Token of your Telegram bot.
- `FREE2FA_TELEGRAM_BOT_LANGUAGE`: (ru or en) Language model.
- `FREE2FA_AUTO_REG_ENABLED`: Automatic registration of new users.
(New users will be created in the database automatically with Telegram ID 0,
on the administrator portal you need to specify the real ID).
- `FREE2FA_BYPASS_ENABLED`: (true/false) Skip users without request with Telegram ID 0.
- `RADIUS_CLIENT_SECRET`: Secret phrase for RADIUS.
I recommend a minimum of 20 characters of letters in different case numbers.
This secret will encrypt the password before passing it to FreeRadius.
- `FREE2FA_TIMEOUT`: Time to wait for login confirmation (10 to 20).
- `RADIUS_START_SERVERS`: Number of initial RADIUS server processes.
- `RADIUS_MAX_SERVERS`: Maximum number of RADIUS server processes.
- `RADIUS_MAX_SPARE_SERVERS`: Maximum number of redundant RADIUS server processes.
- `RADIUS_MIN_SPARE_SERVERS`: The minimum number of redundant RADIUS server processes.
- `ADMIN_SECRET_KEY`: Administrator key (generated if left blank).
Used for secure access to the admin area.
- `RESET_PASSWORD`: Enable password reset function for the admin portal
(ADMIN_SECRET_KEY will be required for reset).
- `ALLOW_API_FAILURE_PASS`: (true/false) Allow users without 2FA if
`api.telegram.org` is unavailable. 
- `ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML`: The dns name of the admin web site.
You should write it in dns or hosts for easy access.
- `RADIUS_CLIENT_IP`: IP radius of the client. It is highly recommended to
specify from which IP to expect requests for authorization.


You will need to change the admin password at the first login.

![screenshot](img/1-2.png)

### How can a user find out his Telegram ID?

A user needs to log in to the bot and write /start or click the button.
The bot will send a message with the user's id in response.

### How do I upgrade from a previous version?

1. Go to the installation directory.
2. ```docker-compose down``` You can add -t 0 if you don't want to wait for completion.
3.  ```docker-compose pull```
4.  ```docker-compose up -d```

If you want, you can see the logs after running 
```shell
docker-compose logs -f
```

### Change History:

**13.02.2024**

In the database, user logins are always stored in ``"domain\username"`` format,
regardless of which format the user entered their credentials in.  
This means that even if a user uses different ways to enter their login credentials, such as:

- `"domain\username"`.
- `"domain.local\username"`.
- `"username@domain.local"`
- `"username@domain"`
- `"username"` (in the case when short names are allowed without specifying the domain),

will be written to the database uniformly as `"domain\username"`.
This rule works the same for all cases, ensuring consistency of data in the database.  

Added control.sh script that provides the ability to configure multiple configurations
on a single server.

**18.02.2024**

An improvement was made to the application logic related to the lack of connection to the
Telegram API.  
Now, if the application fails to connect to Telegram API at startup, the system can continue
to work in bypass mode,  
provided the ALLOW_API_FAILURE_PASS option is enabled. This means that the bot will be
automatically launched as soon as the connection to the API is restored.  
If the connection is lost again after the bot is started, the workaround mechanism will be
triggered, provided that it is enabled. In addition, for users  
who have the Bypass checkbox checked in the control panel, the bypass mode will be activated
permanently regardless of the ALLOW_API_FAILURE_PASS setting.

**01.03.2024**

Admin_html Security Updates.  
As part of strengthening the security of the web application, changes have been made to the
Nginx configuration file,  
including the addition of a number of security headers. These headers are aimed at:

- Improving connection security and enforcing the use of HTTPS.
- Preventing various types of web attacks, including attacks via code injection and spoofing
of cross-site requests.
- Limiting the ability to embed our site content in frames on third-party resources.
- Strengthening defenses against cross-site scripting (XSS) and other types of attacks.

These measures help provide a higher level of security for users, preventing potential threats
and attacks.

**03.03.2024**

The "Free2FA" project offers two additional editions of the application designed to meet specific security needs. Both editions incorporate Telegram push notifications alongside other features:

1. **Edition for RDG (Remote Desktop Gateway)**: This version is tailored for use in remote desktop access systems through RDG gateways. It adds an extra layer of security by integrating two-factor authentication with Telegram push notifications. GitHub repository: [Free2FA4RDG](https://github.com/CLLlAgOB/free2fa4rdg).

2. **Edition with Portal and One-Time Passwords (OTP)**: This version combines portal-based authentication with one-time passwords and Telegram push notifications. It is aimed at organizations and individual users seeking a convenient and secure form of two-factor authentication. GitHub repository: [Free2FAPlus](https://github.com/CLLlAgOB/free2faplus).

These editions expand the functionality of the base "Free2FAPlus" version, providing additional options for securing and managing access to digital resources.