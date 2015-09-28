# general stuff
import sys
import os
import random
import time

# matplot lib stuff
import matplotlib.lines as mlines
import matplotlib as mpl
import matplotlib.pyplot as plt
import math
import numpy as np

# crypto stuff
import hashlib
from Crypto.Cipher import AES

# experiment settings
fileName = sys.argv[1]
minPayloadSize = int(sys.argv[2])
maxPayloadSize = int(sys.argv[3])
dataFileName = sys.argv[4] + ".out"
figureFileName = sys.argv[4] + ".png"
keySize = 256 # so, at least 256 bits of entropy for all keys

class timefunc(object):
	def __init__(self, flag, name):
		self.total = int(flag)
		self.name = name
	def __call__(self, func):
		decorator_self = self
		global times
		def f_timer( *args, **kwargs):
			start = time.time()
			result = func(*args, **kwargs)
			end = time.time()
			# print func.__name__, float(end - start) / float(self.total)
			times[self.name] = float(end - start) / float(self.total)
			return result
		return f_timer

# 0. create the set of names from the file
names = {}
with open(fileName) as fhandle:
	for line in fhandle.readlines():
		name = line.strip()
		components = name.split("/")
		numComponents = len(components)
		if numComponents not in names:
			names[numComponents] = []
		names[numComponents].append(components)
numNames = len(names)

# 1. name component hashing
def hashNames(names):
	hashedNames = []
	reverseMap = {}
	times = []
	for name in names:
		startTime = time.time()
		hashedName = []
		for componentIndex, component in enumerate(name):
			prefix = "".join(name[0:componentIndex + 1])
			hasher = hashlib.sha256()
			hasher.update(prefix)
			hashedName.append(hasher.digest())
		endTime = time.time()
		strName = "/".join(hashedName)
		hashedNames.append(strName)
		reverseMap[strName] = "/".join(name)

		times.append(("/".join(name), strName, float(endTime - startTime)))
	return hashedNames, reverseMap, times

# 2. name decryption/recovery
def reverseNames(hashedNames, reverseMap):
	times = []
	for hashedName in hashedNames:
		startTime = time.time()
		name = reverseMap[hashedName]
		endTime = time.time()
		times.append((name, hashedName, float(endTime - startTime)))
	return times

##### intermediate: create random content.
def createPayloads(hashedNames, reverseMap):
	payloads = {}
	for hashedName in hashedNames:
		# print >> sys.stderr, "\t... " + str(reverseMap[name])
		payloadSize = random.randint(minPayloadSize / 16, maxPayloadSize / 16)
		while payloadSize % 16 != 0:
			payloadSize = random.randint(minPayloadSize, maxPayloadSize)
		payload = os.urandom(16) * payloadSize

		payloads[hashedName] = payload
	return payloads

# 3. content encryption
# @profile
def encryptContent(hashedNames, reverseMap, payloads):
	encryptedPayloads = {}
	times = []
	print "LENGTH OF NAMES = " + str(len(hashedNames))
	nonce = os.urandom(keySize)
	for hashedName in hashedNames:

		startTime = time.time()

		# generate the key based on the nonce plus the name
		hasher = hashlib.sha256()
		hasher.update(str(nonce) + reverseMap[hashedName])
		randomKey = hasher.digest()

		# encrypt the content object payload
		cipher = AES.new(randomKey, AES.MODE_CBC, 'This is an IV456') # TODO: make this IV different?... shouldn't matter for the experiment
		plaintext = payloads[hashedName]

		encryptedPayload = cipher.encrypt(plaintext)

		endTime = time.time()

		encryptedPayloads[hashedName] = ((encryptedPayload, nonce, plaintext))

		times.append((reverseMap[hashedName], hashedName, float(endTime - startTime)))
	return encryptedPayloads, times

# 4. content decryption
# @profile
def decryptContent(hashedNames, reverseMap, encryptedPayloads):
	times = []
	for hashedName in hashedNames:
		startTime = time.time()
		(encryptedPayload, nonce, plaintext) = encryptedPayloads[hashedName]

		hasher = hashlib.sha256()
		hasher.update(str(nonce) + reverseMap[hashedName])
		randomKey = hasher.digest()

		cipher = AES.new(randomKey, AES.MODE_CBC, 'This is an IV456') # TODO: make this IV different?...
		decryptedPayload = cipher.decrypt(encryptedPayload)

		endTime = time.time()

		if decryptedPayload != plaintext:
			raise Exception("Encryption error occurred")

		times.append((reverseMap[hashedName], hashedName, float(endTime - startTime)))

	return times

# Run the protocol, end to end
avg1s = []
avg2s = []
avg3s = []
avg4s = []
lengths = []

outputFile = open(dataFileName, "w")
for nameLength in names:
	print >> sys.stderr, "Length = " + str(nameLength)
	nameCandidates = names[nameLength][:200]

	# emulate the tsec protocol for a single exchange
	print >> sys.stderr, "Step 1..."
	hashedNames, reverseMap, stepOneTimes = hashNames(nameCandidates)
	print >> sys.stderr, "Step 2..."
	stepTwoTimes = reverseNames(hashedNames, reverseMap)
	print >> sys.stderr, "(creating payloads)..."
	payloads = createPayloads(hashedNames, reverseMap)
	print >> sys.stderr, "Step 3..."
	encryptedPayloads, stepThreeTimes = encryptContent(hashedNames, reverseMap, payloads)
	print >> sys.stderr, "Step 4..."
	stepFourTimes = decryptContent(hashedNames, reverseMap, encryptedPayloads)

	# print the average times
	width = 0.35 # for the graph baduh.
	avg1 = sum(map(lambda (n, hn, t) : t, stepOneTimes)) / len(stepOneTimes)
	print >> sys.stderr, avg1
	avg2 = sum(map(lambda (n, hn, t) : t, stepTwoTimes)) / len(stepTwoTimes)
	print >> sys.stderr, avg2
	avg3 = sum(map(lambda (n, hn, t) : t, stepThreeTimes)) / len(stepThreeTimes)
	print >> sys.stderr, avg3
	avg4 = sum(map(lambda (n, hn, t) : t, stepFourTimes)) / len(stepFourTimes)
	print >> sys.stderr, avg4

	# save the data to a file for processing outside of this script
	for (n, hn, t) in stepOneTimes:
		line = str(nameLength) + ",1," + str(t) + "\n"
		outputFile.write(line)
	for (n, hn, t) in stepTwoTimes:
		line = str(nameLength) + ",2," + str(t) + "\n"
		outputFile.write(line)
	for (n, hn, t) in stepThreeTimes:
		line = str(nameLength) + ",3," + str(t) + "\n"
		outputFile.write(line)
	for (n, hn, t) in stepFourTimes:
		line = str(nameLength) + ",4," + str(t) + "\n"
		outputFile.write(line)

	lengths.append(nameLength)
	avg1s.append(avg1)
	avg2s.append(avg2)
	avg3s.append(avg3)
	avg4s.append(avg4)

p1 = plt.bar(lengths, avg1s, width, color='r')	
p2 = plt.bar(lengths, avg2s, width, color='y', bottom=avg1s)#, yerr=menStd)
p3 = plt.bar(lengths, avg3s, width, color='g', bottom=avg2s)#, yerr=menStd)
p4 = plt.bar(lengths, avg4s, width, color='b', bottom=avg3s)#, yerr=menStd)

plt.ylabel('Time (s)')
plt.xlabel('Number of Name Components')
# plt.title('TODO')
# plt.xticks(ind+width/2., ('Hash Obfuscation', 'G2', 'G3', 'G4', 'G5') )
# plt.yticks(np.arange(0,81,10))
plt.legend( (p1[0], p2[0], p3[0], p4[0]), ('Step 1', 'Step 2', 'Step 3', 'Step 4') )

# plt.tight_layout()
plt.show()
plt.savefig(figureFileName)