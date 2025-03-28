// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// This will work for only one room and one booking at a time
contract HotelRoom{
    address payable public owner;
    enum statuses{Vacant, Occupied}
    statuses public currentStatus;
    event Occupy(address _occupant, uint256 _amt);
    constructor(){  
        owner = payable (msg.sender);
        currentStatus = statuses.Vacant;
    }
    modifier costs(uint _amount ){
        require(msg.value>=_amount, "You Don't have enough money!");
        _;
    }
    modifier OnlywhileVacant(){
        require(currentStatus == statuses.Vacant, "Already booked!");
        _;
    }
    function book() external payable OnlywhileVacant costs(1 ether){
        // owner.transfer(msg.value);
        (bool sent,) = owner.call{value: msg.value}("");
        require(sent, "Transaction Failed!");
        // This will keep that the event will only emit when the upper 
        // line executed and the transaction be successful
        currentStatus = statuses.Occupied;
        emit Occupy(msg.sender, msg.value);
    }
    }