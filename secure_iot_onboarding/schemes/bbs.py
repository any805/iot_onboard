from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.toolbox.pairinggroup import PairingGroup, ZR

class BBSGroupSig:
    def __init__(self, group_name='MNT224'):
        self.group = PairingGroup(group_name)
        self.gs = ShortSig(self.group)
        self.gpk = None
        self.gmsk = None
        self.gsk = None

    def keygen(self, n):
        '''Generate group public key, manager secret key, and user secret keys.'''
        self.gpk, self.gmsk, self.gsk = self.gs.keygen(n)
        return self.gpk, self.gmsk, self.gsk

    def sign(self, user_idx, message):
        '''Sign a message as user user_idx.'''
        if self.gpk is None or self.gsk is None:
            raise ValueError("Keys not generated. Call keygen() first.")
        return self.gs.sign(self.gpk, self.gsk[user_idx], message)

    def verify(self, message, signature):
        '''Verify a group signature.'''
        if self.gpk is None:
            raise ValueError("Group public key not set. Call keygen() first.")
        return self.gs.verify(self.gpk, message, signature)