#!/user/bin/env python3
# -*- coding: UTF-8 -*-

"""

This tool is built to validate the SPF(Sender Policy Framework) record of a given domain, 
the validation result is provided in Arabic with explanation of each part of the record mechanisms.
Also, the tool provides some information about the SPF and its importance.

"""

__author__ = "Nourah Altawallah"
__email__ = "Naltawallah@gmail.com"
__license__ = "GPL v3"
__version__ = "1.0.1"

from flask import Flask, render_template, request, Response
import re
import dns
from dns import resolver
from netaddr import *
from collections import Counter

 

def spf_validation(domain):
    spf = Spf(domain)
    validation_result, spf_record, mechanism = spf.check(domain)

    return validation_result, spf_record, mechanism


class Spf:
    
    '''
 
    validation criteria:
    
    1-starts with v=spf1  
    2-ends with all
    3-no extra spaces 
    4-number of DNS lookup<10
    5-string length<255 
    6- no unknown mechanism
    7- only one spf record 
    8- no duplicate ip address
    9- void lookups < 2

    '''

    def __init__(self, domain):
        self.domain = domain
        self.recursion = 0
        self.ip_address = []
        self.test_result = []
        self.mechanisms_result = []
        self.duplicate_ip = []
        self.void_lookup = 0
        self.record = []
        self.ip_network = []  # contains subnet

    def check(self, domain):
        if not self.check_spf(domain):
            return self.test_result, self.record, self.mechanisms_result
        self.check_duplicateIP()
        if self.recursion > 10:  # no lookup
            self.test_result.append(
                {'test': (u'  عدد مرات البحث من الخادم تجاوز الحد ١٠'), 'result': u'نعم', 'status': 'fail'})
        else:
            self.test_result.append(
                {'test': (u'  عدد مرات البحث من الخادم تجاوز الحد ١٠'), 'result': u'لا', 'status': 'pass'})


        return self.test_result, self.record, self.mechanisms_result

    def check_spf(self, domain):

        if domain == self.domain:
            self.record.append({u'  اسم النطاق ': ('%s' % domain)})
        condition, spf_list = self.get_spf(domain)


        if not condition:
            return False

        for spf in spf_list:
            if domain == self.domain:
                self.record.append({u' السجل ': spf})

            self.end_with_all(spf, domain)
            sp = self.check_spaces(spf, domain)
            # spf record after removing extra spaces
            spf = sp
            self.check_string_length(spf, domain)
            self.process_mechanisms(domain, spf)

        return True

    def get_spf(self, domain):
        count = 0
        condition, txt_list = self.get_txtrecord(domain, 'TXT')
        spf_list = []
        if condition:
            reg = re.compile("^(v=spf1) (.*)")

            for txt in txt_list:
                txt = txt[1:len(txt) - 1]
                match = reg.match(txt)
                if match:
                    #count number of SPF records
                    count = count + 1
                    spf_list.append(txt)

            if count > 1:
                if domain == self.domain:
                    self.test_result.append({'test': u'  عدد السجلات ', 'result': '%d' % count, 'status': 'fail'})

            if count == 1:
                if domain == self.domain:
                    self.test_result.append({'test': u'  عدد السجلات ', 'result': '%d' % count, 'status': 'pass'})

            if count == 0:
                if domain == self.domain:
                    self.test_result.append({'test': u'  عدد السجلات ', 'result': u'لا يوجد ', 'status': 'fail'})
                    condition = False
      

            return condition, spf_list

        return condition, str(txt_list)

    def get_txtrecord(self, domain, record):
        item_list = []
        condition = True
        try:
            if self.recursion > 10:
                condition = False
                return condition, item_list
            answers = dns.resolver.query(domain, 'TXT')
            self.recursion = self.recursion + 1
            for item in answers:
                item = item.to_text()
                item_list.append(item)

        except Exception as e:
            s = str(e)
            if 'NOERROR' or 'NXDOMAIN' in s:
                self.void_lookup = self.void_lookup + 1
            condition = False
            self.test_result.append({'test': ' ', 'result': str(e), 'status': 'fail'})

        return condition, item_list

    def end_with_all(self, spf, domain):
        if not spf.endswith('all'):
            if domain == self.domain:
                self.test_result.append({'test': (u'ينتهي السجل ب' 'all'), 'result': u'لا', 'status': 'fail'})

        if domain == self.domain:
            self.test_result.append({'test': (u'ينتهي السجل ب' 'all'), 'result': u'نعم', 'status': 'pass'})

    def check_spaces(self, spf, domain):
        s = spf.split(' ')
        for char in s:
            if '' in char:
                spf = self.remove_extra_spaces(spf)
                return spf

        return spf

    def remove_extra_spaces(self, spf):
        spf = ' '.join(str(spf).split())

        return spf

    def check_string_length(self, spf, domain):
        s = spf.split(' ')
        if len(s) > 255:
            if domain == self.domain:
                self.test_result.append({'test': (u' تجاوز عدد الأحرف المسموح بها'), 'result': u'نعم', 'status': 'fail'})

        if domain == self.domain:
            self.test_result.append({'test': (u' تجاوز عدد الأحرف المسموح بها'), 'result': u'لا', 'status': 'pass'})

    def process_mechanisms(self, domain, spf):
        spf = spf[7:]  # v=spf1
        spf = spf.split(' ')
        for mec in spf:
            if mec[0] not in ['+', '?', '-', '~']:
                mec = '+%s' % mec
            stop = self.process(mec, domain)
            if stop:
                break

    def process(self, rule, domain):
        '''

        :param rule: one mechanism
        :param domain: self.domain or an included domain
        :return: stop if the rule is all
        '''
        stop = False
        actions_list = {
            '+': u'مسموح',
            '-': u'غير مسموح',
            '~': u"سماح مشروط",
            '?': u'طبيعي'
        }
        description_list = {
            'include': u'يسمح لإسم النطاق بالإرسال',
            'ip': u' يسمح للعنوان بالإرسال',
            'all': u" يسمح للكل بالإرسال ",
            'a': u' يسمح للعناوين في السجل بالإرسال',
            'mx': u'يسمح للعناوين في خادم البريد اﻻلكتروني بالإرسال ',
            'redirect': u'التحويل لسجل النطاق الآخر',
            'exists ': u'',

        }

        # Extract action
        action = actions_list[rule[:1]]
        sign=rule[:1]
        rule = rule[1:]

        if rule[:3] == 'ip4':
            if domain == self.domain:
                self.mechanisms_result.append({'prefix': sign, 'action': action, 'mechanism': 'IP4: %s' % rule[4:],
                                               'description': description_list[rule[:2]]})

            if '/' in rule[4:]:
                self.ip_network.append(rule[4:])

            else:
                self.ip_address.append(rule[4:])
            return stop

        elif rule[:3] == 'ip6':
            if domain == self.domain:
                self.mechanisms_result.append({'prefix':sign, 'action': action, 'mechanism': 'IP6: %s' % rule[4:],
                                               'description': description_list[rule[:2]]})

            if '/' in rule[4:]:
                self.ip_network.append(rule[4:])

            else:
                self.ip_address.append(rule[4:])
            return stop

        elif rule[:3] == 'all':
            if domain == self.domain:
                self.mechanisms_result.append({'prefix': sign, 'action': action, 'mechanism': rule[3:],
                                               'description': description_list[rule[:3]]})
            stop = True
            if action == 'pass':

                return stop
            else:

                return stop
        # a
        elif rule[:1] == 'a':
            ip_network = []
            reg = re.match('^a:?(?P<domain>[\w\d\.]+)?/?(?P<prefix_length>[\d]{1,2})?', rule)
            if reg.group('domain') is not None:
                domain = reg.group('domain')
            prefix_length = reg.group('prefix_length')
            self.mechanisms_result.append({'prefix': sign, 'action': action, 'mechanism': rule[:1],
                                           'description': description_list[rule[:1]]})

            # Retrieve A record.
            try:
                answers = resolver.query(domain, 'A')
                self.recursion = self.recursion + 1
                if self.recursion > 10:
                    return stop
                for rdata in answers:
                    if prefix_length is not None:
                        ip_network.append(IPNetwork(str(rdata) + "/" + prefix_length))

                        self.ip_network.append(IPNetwork(str(rdata) + "/" + prefix_length))


                    else:
                        ip_network.append(IPNetwork(str(rdata)))

                        self.ip_address.append(IPNetwork(str(rdata)))




            except Exception as e:
                s = str(e)
                if 'NOERROR' or 'NXDOMAIN' in s:
                    self.void_lookup = self.void_lookup + 1

            return stop

        # mx

        elif rule[:2] == 'mx':
            mx_list = []
            reg = re.match('^mx:?(?P<domain>[\w\d\.]+)?/?(?P<prefix_length>[\d]{1,2})?', rule)

            if reg.group('domain') is not None:
                domain = reg.group('domain')
            prefix_length = reg.group('prefix_length')

            # Retrieve MX record

            try:
                answers = resolver.query(domain, 'MX')
                self.recursion = self.recursion + 1
                if self.recursion > 10:
                    return stop

                for rdata in answers:

                    mx_domain = str(rdata.exchange)
                    mx_list.append(mx_domain)
                    answers = resolver.query(mx_domain, 'A')
                    self.recursion = self.recursion + 1
                    if self.recursion > 10:  # no lookup

                        return stop
                    for rdata in answers:
                        if prefix_length is not None:

                            mx_list.append('IP: ' + str(rdata) + "/" + prefix_length)
                            self.ip_network.append(str(rdata) + "/" + prefix_length)


                        else:

                            mx_list.append('IP: ' + str(rdata))
                            self.ip_address.append(str(rdata))
                mx_list.sort(key=lambda tup: tup[0], reverse=True)
                if domain == self.domain:
                    self.mechanisms_result.append(
                        {'prefix':sign, 'action': action, 'mechanism': 'MX %s' % mx_list})


            except Exception as e:
                s = str(e)
                if 'NOERROR' or 'NXDOMAIN' in s:
                    self.void_lookup = self.void_lookup + 1

            return stop


        elif rule[:3] == 'ptr':
            if domain == self.domain:
                self.test_result.append({'test': (u'ptr(Pointer) للإشارة إلى إسم النطاق من خلال العنوان'), 'result': u'  ينصح بعدم ادراج هذه السجلات', 'status': 'fail'})
            self.recursion = self.recursion + 1
            if self.recursion > 10:
                return stop

            return stop

        elif rule[:7] == 'include':
            if domain == self.domain:
                self.mechanisms_result.append(
                    {'prefix': sign, 'action':   action, 'mechanism': 'Include %s' % rule[8:],
                     'description': description_list[rule[:7]]})

            dom = rule[8:]
            return stop, self.check_spf(dom)

        elif rule[:6] == 'exists':
            self.recursion = self.recursion + 1

            return stop

        elif rule[:8] == 'redirect':
            self.recursion = self.recursion + 1
            self.mechanisms_result.append('Redirect %s' % rule[9:])
            stop == True
            return stop, self.check_spf(rule[8:])
        else:

            self.spf_issues.append(('Rule %s is not managed in %s spf record.' % (rule, domain)))

        return False

    def check_duplicateIP(self):
        '''
        check ip_address list if it contains duplicate ips and append the issue
        '''
        self.duplicate_ip = [k for k, v in Counter(self.ip_address).items() if v > 1]

        for subnet in self.ip_network:

            for address in self.ip_address:

                if IPAddress(address) in IPNetwork(subnet):

                    self.duplicate_ip.append(address)

        if len(self.duplicate_ip) > 0:
            self.test_result.append({'test': (u' يحتوي على عنواين مكررة'), 'result': u'نعم', 'status': 'fail'})

        self.test_result.append({'test': (u' يحتوي على عنواين مكررة'), 'result': u'لا', 'status': 'pass'})


# app section
app = Flask(__name__)


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/postdata', methods=['POST'])
def result():

    domain_name = request.form['domain_name']
    '''	
    	Re-check the domain name validity :

		1- Begin and end with alphanumeric characters
		2- Doesn’t contain any special character except dashes (-) and dots (.)
		3- Maximum length of each label is 63 characters
		4- Top-level domain has Min 2 and Max 6 characters 
		
	 '''
    regex = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$'
    match = re.match(regex,domain_name)
    
    if match:
        result, record, mechanisms = spf_validation(domain_name)
        return render_template('result.html', result=result, record=record, mechanisms=mechanisms)
    else :
        return render_template('index.html' , msg=u' الرجاء كتابة اسم النطاق بشكل صحيح')






if __name__ == '__main__':
    app.run()
