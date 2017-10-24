from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
from recon.mixins.threads import ThreadingMixin
from json import loads
import dns.resolver

"""
Ceci est un module pour recon-ng. A placer dans recon-ng/modules/recon/domains-hosts/.
"""


class Module(BaseModule, ResolverMixin, ThreadingMixin):

	meta = {
		'name': 'securitytrails.com subdomain harvester',
		'author': 'b0z - bastien@faure.io',
		'description': 'Harvests subdomains name in the securitytrails DNS database',
		'comments': 'Good luck',
		'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
	}

	def module_run(self, domains):
		base_url = "https://app.securitytrails.com/api/domain/info/%s"
		for domain in domains:
			self.heading(domain, level=0)
			url = base_url % domain
			resp = self.request(url)
			if resp.status_code != 200:
				self.alert('An error has been encountered.')
				break
			content = loads(resp.text)
			try:
				subdomains = content["result"]["subdomains"]
				subdomains = map(lambda x: "%s.%s" % (x, domain), subdomains)
				resolver = self.get_resolver()
				self.thread(subdomains, resolver)
			except KeyError:
				self.error("No subdomains for %s" % domain)

	def module_thread(self, host, resolver):
		max_attempts = 3
		attempt = 0
		while attempt < max_attempts:
			try:
				answers = resolver.query(host)
			except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
				self.verbose('%s => No record found.' % (host))
			except dns.resolver.Timeout:
				self.verbose('%s => Request timed out.' % (host))
				attempt += 1
				continue
			else:
				# process answers
				for answer in answers.response.answer:
					for rdata in answer:
						if rdata.rdtype in (1, 5):
							if rdata.rdtype == 1:
								address = rdata.address
								self.alert('%s => (A) %s' % (host, address))
								self.add_hosts(host, address)
							if rdata.rdtype == 5:
								cname = rdata.target.to_text()[:-1]
								self.alert('%s => (CNAME) %s' % (host, cname))
								self.add_hosts(cname)
								# add the host in case a CNAME exists without an A record
								self.add_hosts(host)
			# break out of the loop
			attempt = max_attempts
