from ...config import Configuration


class IdentityProof(Configuration):
    encoding = 'utf-8'
    """
    Structure of transmitted proof of identity
    """
    def __init__(self, uuid, digest, approval):
        self.uuid = uuid  # approver
        self.digest = digest  # block hash
        self.approval = approval  # yea/nay

    def to_dict(self):
        return dict(uuid=self.uuid, digest=self.digest, approval=self.approval)

