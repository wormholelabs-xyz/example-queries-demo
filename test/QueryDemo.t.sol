// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {QueryDemo} from "../src/QueryDemo.sol";
import {WormholeMock} from "wormhole-solidity-sdk/testing/helpers/WormholeMock.sol";

contract QueryDemoTest is Test {
    QueryDemo public demo;

    function setUp() public {
        WormholeMock wormholeMock = new WormholeMock();
        demo = new QueryDemo(address(this), address(wormholeMock), 2);
    }

    function test_getMyCounter() public view {
        assertEq(demo.getMyCounter(), 0);
    }
}
