from abc import ABC
from .agreement import AgreementProtocol, AgreementVoter, AgreementProof
from ..system import encoding

class AgreementByWork(AgreementProtocol, ABC):
    """
    Agreement by computation capability
    Still abstract
    """
    DIFFICULTY = 2

    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter]):
        super().__init__(myself, peers)
        self._approved = []

    def prove(self, blob):
        nonce = 0
        computed_hash = blob.get_hash()
        # WARNING: this is *designed* to take some time
        try:
            while not computed_hash.startswith(b'0' * self.DIFFICULTY):
                nonce += 1
                computed_hash = blob.get_hash(str(nonce).encode(encoding))
        except MemoryError:
            pass
        return AgreementProof(self.myself.uuid, computed_hash, True)

    def verify(self, blob, proof, sig):
        self._pre_verify(blob, proof, sig)
        if proof.digest.startswith(b'0' * self.DIFFICULTY) and proof.digest == blob.get_hash(proof.nonce):
            self._approved.append(blob)
        return True

    def finalize(self, blob):
        if blob in self._approved:
            self._approved.remove(blob)
            return True
        return False
