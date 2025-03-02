
import traceback
import asyncio
from asysocks.unicomm.common.scanner.common import *
from atds.common.factory import MSSQLConnectionFactory
from asyauth.protocols.ntlm.structures.serverinfo import NTLMSERVERINFO_TSV_HDR, NTLMServerInfo
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol
from atds.common.target import MSSQLTarget

class MSSQLQueryRes:
	def __init__(self, res:NTLMServerInfo):
		self.res = res

	def get_header(self):
		return NTLMSERVERINFO_TSV_HDR

	def to_json(self):
		return self.res.to_json()

	def to_line(self, separator = '\t'):
		return self.res.to_tsv(separator)
	
	def to_dict(self):
		return self.res.to_dict()
	

class MSSQLFingerScanner:
	def __init__(self, factory:MSSQLConnectionFactory, query:str):
		self.factory:MSSQLConnectionFactory = factory
		self.query = query

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await asyncio.wait_for(connection.connect(), timeout = 5)
				if err is not None:
					raise err

				cursor = connection.get_cursor()
				await cursor.execute(self.query)
				await out_queue.put(ScannerData(target, MSSQLQueryRes(res)))
		
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			print(f"Error: {e} | Traceback: {tb}")
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
		

async def amain():
	import argparse
	from asysocks.unicomm.common.scanner.targetgen import UniTargetGen, UniCredentialGen
	from asysocks.unicomm.common.scanner.scanner import UniScanner
	

	parser = argparse.ArgumentParser()
	parser.add_argument("--out-file", type=str, required=False)
	parser.add_argument("--worker-count", type=int, required=False, default=100)
	parser.add_argument("--timeout", type=int, required=False, default=10)
	parser.add_argument("--no-progress", action='store_true', required=False)
	parser.add_argument("--errors", action='store_true', required=False)
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
	args = parser.parse_args()

	target = MSSQLTarget(
		ip = '999.999.999.999',
		database = 'master',
	)
	cred = UniCredential(
		secret = 'test',
		stype = asyauthSecret.PASSWORD,
		protocol = asyauthProtocol.NTLM,
		domain = 'WORKGROUP',
		username = 'sa',
	)	
	factory = MSSQLConnectionFactory(target, cred)
	executor = MSSQLFingerScanner(factory)
	tgen = UniTargetGen.from_list(args.targets)
	scanner = UniScanner('MSSQLFingerScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
	await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
	return

if __name__ == "__main__":
	asyncio.run(amain())
	