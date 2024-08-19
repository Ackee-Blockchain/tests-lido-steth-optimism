from wake.testing import *
from pytypes.source.contracts.optimism.L1LidoTokensBridge import L1LidoTokensBridge
from pytypes.source.contracts.optimism.L2ERC20ExtendedTokensBridge import L2ERC20ExtendedTokensBridge
from pytypes.source.contracts.token.ERC20BridgedPermit import ERC20BridgedPermit
from pytypes.source.contracts.token.ERC20RebasableBridgedPermit import ERC20RebasableBridgedPermit
from pytypes.source.contracts.proxy.OssifiableProxy import OssifiableProxy


@chain.connect(fork="http://localhost:8545")
def test_upgrade_mainnet():
    bridge_proxy = OssifiableProxy("0x76943C0D61395d8F2edF9060e1533529cAe05dE6")

    new_impl = L1LidoTokensBridge.deploy(Address.ZERO, Address.ZERO, Address.ZERO, Address.ZERO, Address.ZERO, Address.ZERO)

    bridge_proxy.proxy__upgradeTo(new_impl, from_=bridge_proxy.proxy__getAdmin())

    bridge = L1LidoTokensBridge(bridge_proxy)
    bridge.finalizeUpgrade_v2()


@chain.connect(fork="https://optimism-rpc.publicnode.com")
def test_upgrade_optimism():
    wsteth_proxy = OssifiableProxy("0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb")
    bridge_proxy = OssifiableProxy("0x8E01013243a96601a86eb3153F0d9Fa4fbFb6957")

    steth = ERC20RebasableBridgedPermit.deploy("stETH", "stETH", "2.0", 18, wsteth_proxy, Address.ZERO, bridge_proxy)

    new_impl = L2ERC20ExtendedTokensBridge.deploy(Address.ZERO, Address.ZERO, Address.ZERO, Address.ZERO, wsteth_proxy, steth)

    bridge_proxy.proxy__upgradeTo(new_impl, from_=bridge_proxy.proxy__getAdmin())

    bridge = L2ERC20ExtendedTokensBridge(bridge_proxy)
    bridge.finalizeUpgrade_v2()

    new_impl = ERC20BridgedPermit.deploy("Wrapped stETH", "wstETH", "2.0", 18, bridge_proxy)

    wsteth_proxy.proxy__upgradeTo(new_impl, from_=wsteth_proxy.proxy__getAdmin())

    wsteth = ERC20BridgedPermit(wsteth_proxy)
    wsteth.finalizeUpgrade_v2("wstETH", "2.0")
