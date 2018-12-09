import subprocess
import requests
import json
import argparse
import sys

class Conoha:
	def __init__(self, config = "./config"):
		self.path = { "config": config }
		self.header = { "Accept": "application/json", "Content-Type": "application/json" }
		self.sess = requests.Session()
		self.config = self.load_config()
		self.url = {
			"dns": None
		}
		self.setUserToken()

	def load_config(self):
		with open(self.path["config"], "r") as f:
			result = f.read()
		result = json.loads(result)
		return result

	def setUserToken(self):
		rurl = "https://identity.tyo1.conoha.io/v2.0/tokens"
		data = {
			"auth": {
				"passwordCredentials": {
					"username": self.config["user"],
					"password": self.config["passwd"],
					"tenantId": self.config["tenant"]
				}
			}
		}

		result = self.sess.post(rurl, data=json.dumps(data)).json()
		self.header["X-Auth-Token"] = result["access"]["token"]["id"]
		return result

	def setDNS(self, version, domain_name, rname, rtype, rdata, rttl=3600):
		url = "https://dns-service.tyo1.conoha.io/"
		result = self.sess.get(url).json()
		versions = []
		for item in result["versions"]["values"]:
			versions += [ item["id"] ]

		if version not in versions:
			raise Exception("DNS api version({}) not supported".format(version))

		idx = versions.index(version)
		self.url["dns"] = result["versions"]["values"][idx]["links"][0]["href"]
		rurl = "{}/domains".format(self.url["dns"])
		result = self.sess.get(rurl, headers=self.header).json()

		domains = []
		for item in result["domains"]:
			domains += [ item["name"][:-1] ]
		if domain_name not in domains:
			raise Exception("DNS name({}) is not exist".format(domain_name))

		idx = domains.index(domain_name)
		dns_uuid = result["domains"][idx]["id"]
		
		rurl = "{}/domains/{}/records".format(self.url["dns"], dns_uuid)
		data = {
			"name": rname,
			"type": rtype,
			"data": rdata,
			"ttl": rttl
		}

		result = self.sess.post(rurl, headers=self.header, data=json.dumps(data)).json()
		return result

	def delRecord(self, rResult):
		url = "{}/domains/{}/records/{}".format(self.url["dns"], rResult["domain_id"], rResult["id"])
		self.sess.delete(url, headers=self.header)
		
class wildcert:
	def __init__(self, cmd):
		self.con = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	def recvline(self):
		return self.recvuntil("\n")

	def recvuntil(self, rmsg):
		r = self.con.stdout.read(1)
		while rmsg not in r:
			r += self.con.stdout.read(1)
		return r

	def send(self, msg):
		self.con.stdin.write(msg)

	def sendafter(self, rmsg, msg):
		r = self.recvuntil(rmsg)
		self.send(msg)
		return r

	def sendline(self, msg):
		self.con.stdin.write(msg + '\n')

	def sendlineafter(self, rmsg, msg):
		r = self.recvuntil(rmsg)
		self.sendline(msg)
		return r

	def interactive(self):
		return self.con.stdout.read()

	def getError(self):
		return self.con.stderr.read()

parser = argparse.ArgumentParser(description='auto letsencrypt wildcard certificator')
parser.add_argument("-d", "--domain", dest="domain", help="")

if len(sys.argv) <= 1:
	parser.print_help()
	exit(-1)

args = parser.parse_args()
domain = args.domain

conoha = Conoha()
wc = wildcert("certbot --force-renew -d *.{} --manual --preferred-challenges dns-01 --server https://acme-v02.api.letsencrypt.org/directory certonly".format(domain))

wc.sendlineafter("(Y)es/(N)o: ", "Y")
wc.recvuntil("_acme-challenge.{} with the following value:\n\n".format(domain))
txt_data = wc.recvline()[:-1] # without \n

result = conoha.setDNS("v1", domain, "_acme-challenge.{}.".format(domain), "TXT", txt_data)

wc.sendline("")
wc.interactive()

conoha.delRecord(result)