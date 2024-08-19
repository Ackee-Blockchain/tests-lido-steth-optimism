from dataclasses import dataclass
from typing import Dict, Tuple, Union
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.contracts.optimism.L1LidoTokensBridge import L1LidoTokensBridge, IERC20WstETH
from pytypes.source.contracts.optimism.L2ERC20ExtendedTokensBridge import L2ERC20ExtendedTokensBridge
from pytypes.source.contracts.optimism.stubs.CrossDomainMessengerStub import CrossDomainMessengerStub
from pytypes.source.contracts.optimism.TokenRateOracle import TokenRateOracle
from pytypes.source.contracts.optimism.OpStackTokenRatePusher import OpStackTokenRatePusher
from pytypes.source.contracts.token.ERC20RebasableBridgedPermit import ERC20RebasableBridgedPermit
from pytypes.source.contracts.token.ERC20BridgedPermit import ERC20BridgedPermit
from pytypes.tests.Create3Deployer import Create3Deployer
from pytypes.tests.IStEth import IStEth
from pytypes.tests.IWstEth import IWstEth

from pytypes.openzeppelin.contracts.proxy.ERC1967.ERC1967Proxy import ERC1967Proxy

from pytypes.source.contracts.lido.TokenRateNotifier import TokenRateNotifier


@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint256
    nonce: uint256
    deadline: uint256


l1 = Chain()
l2 = Chain()


class BridgeFuzzTest(FuzzTest):
    l1_create3: Create3Deployer
    l2_create3: Create3Deployer

    l1_messenger: CrossDomainMessengerStub
    l2_messenger: CrossDomainMessengerStub

    l1_wsteth: IWstEth
    l2_wsteth: ERC20BridgedPermit

    l1_steth: IStEth
    l2_steth: ERC20RebasableBridgedPermit

    l1_token_rate_notifier: TokenRateNotifier
    l1_token_rate_pusher: OpStackTokenRatePusher

    l2_token_rate_oracle: TokenRateOracle

    l1_bridge: L1LidoTokensBridge
    l2_bridge: L2ERC20ExtendedTokensBridge

    shares: Dict[Account, uint]

    def pre_sequence(self) -> None:
        admin = l1.accounts[0].address
        assert l2.accounts[0].address == admin

        self.l1_create3 = Create3Deployer.deploy(chain=l1)
        self.l2_create3 = Create3Deployer.deploy(chain=l2)

        self.l1_messenger = CrossDomainMessengerStub.deploy(chain=l1)
        self.l2_messenger = CrossDomainMessengerStub.deploy(chain=l2)

        self.l1_bridge = L1LidoTokensBridge(self.l1_create3.getAddress(
            keccak256(b"L1LidoTokensBridge"),
        ), chain=l1)
        self.l2_bridge = L2ERC20ExtendedTokensBridge(self.l2_create3.getAddress(
            keccak256(b"L2ERC20ExtendedTokensBridge"),
        ), chain=l2)

        self.l1_wsteth = IWstEth("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", chain=l1)
        self.l2_wsteth = ERC20BridgedPermit(ERC1967Proxy.deploy(
            ERC20BridgedPermit.deploy("wstETH", "wstETH", "1.0", 18, self.l2_bridge, chain=l2),
            b"",
            chain=l2,
        ))
        self.l2_wsteth.initialize("wstETH", "wstETH", "1.0")

        self.l1_token_rate_notifier = TokenRateNotifier.deploy(admin, chain=l1)
        self.l1_token_rate_pusher = OpStackTokenRatePusher(self.l1_create3.getAddress(
            keccak256(b"OpStackTokenRatePusher"),
        ), chain=l1)
        self.l2_token_rate_oracle = TokenRateOracle(self.l2_create3.getAddress(
            keccak256(b"TokenRateOracle"),
        ), chain=l2)

        assert self.l1_token_rate_pusher.address == self.l1_create3.deploy_(
            keccak256(b"OpStackTokenRatePusher"),
            OpStackTokenRatePusher.get_creation_code() + abi.encode(
                self.l1_messenger,
                self.l1_wsteth,
                self.l2_token_rate_oracle,
                uint(0),
            )
        ).return_value

        impl = TokenRateOracle.deploy(
            self.l2_messenger,
            self.l2_bridge,
            self.l1_token_rate_pusher.address,
            uint(0),
            uint(5),
            uint(100),
            chain=l2,
        )
        assert self.l2_token_rate_oracle.address == self.l2_create3.deploy_(
            keccak256(b"TokenRateOracle"),
            ERC1967Proxy.get_creation_code() + abi.encode(impl, b""),
        ).return_value

        self.l1_steth = IStEth("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", chain=l1)
        self.l2_steth = ERC20RebasableBridgedPermit(ERC1967Proxy.deploy(
            ERC20RebasableBridgedPermit.deploy("stETH", "stETH", "1.0", 18, self.l2_wsteth, self.l2_token_rate_oracle, self.l2_bridge, chain=l2),
            b"",
            chain=l2,
        ))
        self.l2_steth.initialize("stETH", "stETH", "1.0")

        impl = L1LidoTokensBridge.deploy(
            self.l1_messenger,
            self.l2_bridge.address,
            self.l1_wsteth,
            self.l1_steth,
            self.l2_wsteth.address,
            self.l2_steth.address,
            chain=l1,
        )
        assert self.l1_bridge.address == self.l1_create3.deploy_(
            keccak256(b"L1LidoTokensBridge"),
            ERC1967Proxy.get_creation_code() + abi.encode(impl, b""),
        ).return_value

        impl = L2ERC20ExtendedTokensBridge.deploy(
            self.l2_messenger,
            self.l1_bridge.address,
            self.l1_wsteth.address,
            self.l1_steth.address,
            self.l2_wsteth,
            self.l2_steth,
            chain=l2,
        )
        assert self.l2_bridge.address == self.l2_create3.deploy_(
            keccak256(b"L2ERC20ExtendedTokensBridge"),
            ERC1967Proxy.get_creation_code() + abi.encode(impl, b""),
        ).return_value

        self.l1_bridge.initialize(admin)
        self.l2_bridge.initialize(admin)

        self.l1_bridge.grantRole(self.l1_bridge.DEPOSITS_ENABLER_ROLE(), admin)
        self.l1_bridge.grantRole(self.l1_bridge.DEPOSITS_DISABLER_ROLE(), admin)
        self.l1_bridge.grantRole(self.l1_bridge.WITHDRAWALS_ENABLER_ROLE(), admin)
        self.l1_bridge.grantRole(self.l1_bridge.WITHDRAWALS_DISABLER_ROLE(), admin)
        self.l1_bridge.enableDeposits()
        self.l1_bridge.enableWithdrawals()

        self.l2_bridge.grantRole(self.l2_bridge.DEPOSITS_ENABLER_ROLE(), admin)
        self.l2_bridge.grantRole(self.l2_bridge.DEPOSITS_DISABLER_ROLE(), admin)
        self.l2_bridge.grantRole(self.l2_bridge.WITHDRAWALS_ENABLER_ROLE(), admin)
        self.l2_bridge.grantRole(self.l2_bridge.WITHDRAWALS_DISABLER_ROLE(), admin)
        self.l2_bridge.enableDeposits()
        self.l2_bridge.enableWithdrawals()

        self.l1_token_rate_notifier.addObserver(self.l1_token_rate_pusher)

        self.l2_token_rate_oracle.initialize(*self.get_rate())

        l1.tx_callback = self.relay
        l2.tx_callback = self.relay

        self.shares = {}

        for account in l1.accounts:
            self.shares[account] = self.l1_steth.sharesOf(account) + self.l1_wsteth.balanceOf(account)

        for account in l2.accounts:
            self.shares[account] = 0


    def relay(self, tx: TransactionAbc):
        destination_messenger = self.l1_messenger if tx.chain == l2 else self.l2_messenger

        for event in tx.events:
            if isinstance(event, CrossDomainMessengerStub.SentMessage):
                destination_messenger.setXDomainMessageSender(event.sender)
                destination_messenger.relayMessage(event.target, event.sender, event.message, event.messageNonce, from_=random_account(chain=destination_messenger.chain))

        if destination_messenger.chain == l2 and l2.blocks["latest"].timestamp < l1.blocks["latest"].timestamp:
            l2.set_next_block_timestamp(l1.blocks["latest"].timestamp)

    def get_rate(self) -> Tuple[uint, uint]:
        return IERC20WstETH(self.l1_wsteth).stEthPerToken(), l1.blocks["latest"].timestamp

    def post_invariants(self) -> None:
        if random.random() < 0.7:
            self.l1_token_rate_notifier.handlePostTokenRebase(0, 0, 0, 0, 0, 0, 0)

    def approve(self, token: Union[ERC20RebasableBridgedPermit, ERC20BridgedPermit], from_: Account, spender: Account, amount: uint):
        if random_bool():
            token.approve(spender, amount, from_=from_)
        else:
            deadline = token.chain.blocks["latest"].timestamp + 3600
            permit = Permit(from_.address, spender.address, amount, token.nonces(from_), deadline)

            name = "stETH" if token == self.l2_steth else "wstETH"
            signature = from_.sign_structured(
                permit,
                Eip712Domain(
                    name=name,
                    version="1.0",
                    chainId=token.chain.chain_id,
                    verifyingContract=token.address,
                )
            )
            token.permit(
                from_,
                spender,
                amount,
                deadline,
                signature[64],
                signature[:32],
                signature[32:64],
                from_=random_account(chain=token.chain),
            )

    @flow()
    def flow_l1_to_l2(self):
        sender = random_account(predicate=lambda a: a!= l1.accounts[0], chain=l1)
        ether = random_int(10 ** 16, 10 ** 19)
        sender.balance += ether

        wsteth = random_bool()
        if wsteth:
            l1_token = self.l1_wsteth
            l2_token = self.l2_wsteth
        else:
            l1_token = self.l1_steth
            l2_token = self.l2_steth

        shares = self.l1_steth.submit(Address.ZERO, from_=sender, value=ether).return_value
        self.shares[sender] += shares

        amount = self.l1_steth.getPooledEthByShares(shares)
        transferred_shares = self.l1_steth.getSharesByPooledEth(amount)

        if wsteth:
            self.l1_steth.approve(self.l1_wsteth, amount, from_=sender)
            amount = self.l1_wsteth.wrap(amount, from_=sender).return_value

        l1_token.approve(self.l1_bridge, amount, from_=sender)

        sender_before = l1_token.balanceOf(sender)

        if random_bool():
            recipient = Account(sender.address, chain=l2)
            recipient_before = l2_token.balanceOf(recipient)

            self.l1_bridge.depositERC20(l1_token, l2_token.address, amount, 0, b"", from_=sender)
        else:
            recipient = random_account(chain=l2)
            recipient_before = l2_token.balanceOf(recipient)

            self.l1_bridge.depositERC20To(l1_token, l2_token.address, recipient.address, amount, 0, b"", from_=sender)

        self.shares[sender] -= transferred_shares
        self.shares[recipient] += transferred_shares

        error1 = l1_token.balanceOf(sender) - (sender_before - amount)
        error2 = l2_token.balanceOf(recipient) - (recipient_before + amount)
        print(f"L1 token error: {error1}, L2 token error: {error2}")

        #assert l1_token.balanceOf(sender) == sender_before - amount
        #assert l2_token.balanceOf(recipient) == recipient_before + amount

    @flow()
    def flow_l2_wrap(self):
        accounts = [a for a in l2.accounts if self.l2_wsteth.balanceOf(a) > 0]
        if not accounts:
            return

        account = random.choice(accounts)
        amount = random_int(0, self.l2_wsteth.balanceOf(account) // 2, edge_values_prob=0.2)

        self.approve(self.l2_wsteth, account, self.l2_steth, amount)

        with may_revert(ERC20RebasableBridgedPermit.ErrorZeroSharesWrap) as exc:
            tx = self.l2_steth.wrap(amount, from_=account)

        if exc.value is None:
            assert amount != 0
            tokens_amount = self.l2_steth.getTokensByShares(amount)
            assert tx.events == [
                ERC20BridgedPermit.Approval(account.address, self.l2_steth.address, 0),
                ERC20BridgedPermit.Transfer(account.address, self.l2_steth.address, amount),
                ERC20RebasableBridgedPermit.Transfer(Address.ZERO, account.address, tokens_amount),
                ERC20RebasableBridgedPermit.TransferShares(Address.ZERO, account.address, amount),
            ]
        else:
            assert amount == 0

    @flow()
    def flow_l2_unwrap(self):
        accounts = [a for a in l2.accounts if self.l2_steth.balanceOf(a) > 0]
        if not accounts:
            return

        account = random.choice(accounts)
        tokens_amount = random_int(0, self.l2_steth.balanceOf(account) // 2, edge_values_prob=0.2)
        shares_amount = self.l2_steth.getSharesByTokens(tokens_amount)

        with may_revert(ERC20RebasableBridgedPermit.ErrorZeroTokensUnwrap) as exc:
            tx = self.l2_steth.unwrap(tokens_amount, from_=account)

        if exc.value is None:
            assert tokens_amount != 0
            assert tx.events == [
                ERC20RebasableBridgedPermit.Transfer(account.address, Address.ZERO, self.l2_steth.getTokensByShares(shares_amount)),
                ERC20RebasableBridgedPermit.TransferShares(account.address, Address.ZERO, shares_amount),
                ERC20BridgedPermit.Transfer(self.l2_steth.address, account.address, shares_amount)
            ]
        else:
            assert tokens_amount == 0

    @flow()
    def flow_transfer_shares(self):
        owners = [a for a in l2.accounts if self.l2_steth.sharesOf(a) > 0]
        if not owners:
            return

        owner = random.choice(owners)
        recipient = random_account(chain=l2)
        shares_amount = random_int(0, self.l2_steth.sharesOf(owner) // 2, edge_values_prob=0.2)
        tokens_amount = self.l2_steth.getTokensByShares(shares_amount)

        tx = self.l2_steth.transferShares(recipient, shares_amount, from_=owner)

        assert tx.events == [
            ERC20RebasableBridgedPermit.Transfer(owner.address, recipient.address, tokens_amount),
            ERC20RebasableBridgedPermit.TransferShares(owner.address, recipient.address, shares_amount),
        ]

        self.shares[owner] -= shares_amount
        self.shares[recipient] += shares_amount

    @flow()
    def flow_transfer_shares_from(self):
        owners = [a for a in l2.accounts if self.l2_steth.sharesOf(a) > 0]
        if not owners:
            return

        owner = random.choice(owners)
        sender = random_account(chain=l2)
        recipient = random_account(chain=l2)
        shares_amount = random_int(0, self.l2_steth.sharesOf(owner) // 2, edge_values_prob=0.2)
        tokens_amount = self.l2_steth.getTokensByShares(shares_amount)

        self.approve(self.l2_steth, owner, sender, tokens_amount)
        tx = self.l2_steth.transferSharesFrom(owner, recipient, shares_amount, from_=sender)

        assert tx.events == [
            ERC20RebasableBridgedPermit.Approval(owner.address, sender.address, 0),
            ERC20RebasableBridgedPermit.Transfer(owner.address, recipient.address, tokens_amount),
            ERC20RebasableBridgedPermit.TransferShares(owner.address, recipient.address, shares_amount),
        ]

        self.shares[owner] -= shares_amount
        self.shares[recipient] += shares_amount

    @flow()
    def flow_transfer(self):
        token = random.choice([self.l2_steth, self.l2_wsteth])
        owners = [a for a in l2.accounts if token.balanceOf(a) > 0]
        if not owners:
            return

        owner = random.choice(owners)
        recipient = random_account(chain=l2)
        amount = random_int(0, token.balanceOf(owner) // 2, edge_values_prob=0.2)

        tx = token.transfer(recipient, amount, from_=owner)

        if token == self.l2_steth:
            shares_amount = self.l2_steth.getSharesByTokens(amount)

            assert tx.events == [
                ERC20RebasableBridgedPermit.Transfer(owner.address, recipient.address, amount),
                ERC20RebasableBridgedPermit.TransferShares(owner.address, recipient.address, shares_amount),
            ]

            self.shares[owner] -= shares_amount
            self.shares[recipient] += shares_amount
        else:
            assert tx.events == [ERC20BridgedPermit.Transfer(owner.address, recipient.address, amount)]

            self.shares[owner] -= amount
            self.shares[recipient] += amount

    @flow()
    def flow_transfer_from(self):
        token = random.choice([self.l2_steth, self.l2_wsteth])
        owners = [a for a in l2.accounts if token.balanceOf(a) > 0]
        if not owners:
            return

        owner = random.choice(owners)
        sender = random_account(chain=l2)
        recipient = random_account(chain=l2)
        amount = random_int(0, token.balanceOf(owner) // 2, edge_values_prob=0.2)

        self.approve(token, owner, sender, amount)
        tx = token.transferFrom(owner, recipient, amount, from_=sender)

        if token == self.l2_steth:
            shares_amount = self.l2_steth.getSharesByTokens(amount)

            assert tx.events == [
                ERC20RebasableBridgedPermit.Approval(owner.address, sender.address, 0),
                ERC20RebasableBridgedPermit.Transfer(owner.address, recipient.address, amount),
                ERC20RebasableBridgedPermit.TransferShares(owner.address, recipient.address, shares_amount),
            ]

            self.shares[owner] -= shares_amount
            self.shares[recipient] += shares_amount
        else:
            assert tx.events == [
                ERC20BridgedPermit.Approval(owner.address, sender.address, 0),
                ERC20BridgedPermit.Transfer(owner.address, recipient.address, amount),
            ]

            self.shares[owner] -= amount
            self.shares[recipient] += amount

    @flow()
    def flow_l2_to_l1(self):
        wsteth = random_bool()
        if wsteth:
            l1_token = self.l1_wsteth
            l2_token = self.l2_wsteth
        else:
            l1_token = self.l1_steth
            l2_token = self.l2_steth

        senders = [a for a in l2.accounts if l2_token.balanceOf(a) > 0]
        if not senders:
            return

        sender = random.choice(senders)
        amount = random_int(0, l2_token.balanceOf(sender) // 2, edge_values_prob=0.2)

        if wsteth:
            transferred_shares = amount
        else:
            transferred_shares = self.l2_steth.getSharesByTokens(amount)

        sender_before = l2_token.balanceOf(sender)

        if random_bool():
            recipient = Account(sender.address, chain=l1)
            recipient_before = l1_token.balanceOf(recipient)
            tx = self.l2_bridge.withdraw(l2_token, amount, 0, b"", from_=sender)
        else:
            recipient = random_account(chain=l1)
            recipient_before = l1_token.balanceOf(recipient)
            tx = self.l2_bridge.withdrawTo(l2_token, recipient.address, amount, 0, b"", from_=sender)

        self.shares[sender] -= transferred_shares
        self.shares[recipient] += transferred_shares

        error = self.shares[recipient] - self.l1_steth.sharesOf(recipient) - self.l1_wsteth.balanceOf(recipient)
        assert abs(error) <= 1  # wrapping/unwrapping error
        self.shares[recipient] -= error

        #assert l2_token.balanceOf(sender) == sender_before - amount
        #assert l1_token.balanceOf(recipient) == recipient_before + amount

    @invariant()
    def invariant_shares(self):
        for account in l1.accounts:
            assert self.shares[account] == self.l1_steth.sharesOf(account) + self.l1_wsteth.balanceOf(account)

        for account in l2.accounts:
            assert self.shares[account] == self.l2_steth.sharesOf(account) + self.l2_wsteth.balanceOf(account)


@l1.connect(fork="http://localhost:8545")
@l2.connect()
def test_bridge():
    BridgeFuzzTest().run(10, 10_000)
