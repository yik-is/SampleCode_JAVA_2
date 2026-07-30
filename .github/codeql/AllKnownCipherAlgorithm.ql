/**
 * @name All known algorithms
 * @description Outputs operations where the algorithm used is a known algorithm.
 * @id java/quantum/slices/known-operation-algorithm
 * @kind problem
 * @tags quantum
 *       experimental
 */

import java
import experimental.quantum.Language



string getUsage(Crypto::OperationNode op) {
	if op instanceof Crypto::KeyOperationNode
	then result = op.(Crypto::KeyOperationNode).getKeyOperationSubtype().toString()
	else result = op.toString()
	//result = op.(Crypto::KeyOperationNode).getKeyOperationSubtype().toString()
}

int getKeySize (Crypto::OperationNode op, Crypto::AlgorithmNode  a) {

	if op instanceof Crypto::KeyCreationOperationNode /*and a instanceof Crypto::KeyOperationAlgorithmNode*/
	then (
		result = op.(Crypto::KeyCreationOperationNode).getAKeySizeSource().asElement().(Literal).getValue().toInt() 
	)
	else  (
	
		if op instanceof Crypto::KeyDerivationOperationNode
		then result = op.(Crypto::KeyDerivationOperationNode).getOutputKeySize().asElement().(Literal).getValue().toInt()
		else (
			if op.toString() = "HashOperation" 
			then (
			result = a.(Crypto::HashAlgorithmNode).getDigestLength()
			)
			else (

				if exists(op.getAKnownAlgorithm().(Crypto::KeyOperationAlgorithmNode).getKeySizeFixed())
				then
					result = op.getAKnownAlgorithm().(Crypto::KeyOperationAlgorithmNode).getKeySizeFixed()
				else
					result = 0
				
			)
			//result = 0
		)
	)

	//result = 0
}



from Crypto::OperationNode op, Crypto::AlgorithmNode  a
where 
a = op.getAKnownAlgorithm()


//select op, a.getAlgorithmName(),  op.toString(), getKeySize(op, a) as keysize, getUsage(op) as usage,op.getLocation()
select op, "{\"msg\":\"\", \"alg\":\"" + a.getAlgorithmName() + "\", \"usage\":\"" + getUsage(op) + "\"  , \"keySize\":" + getKeySize(op, a) + "}"