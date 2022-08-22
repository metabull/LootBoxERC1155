// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./interfaces/ICancellationRegistry.sol";

contract LootBox is ERC1155Supply, Ownable {
    using ECDSA for bytes32;
    using Strings for uint256;

    // The name of the token ("Bullieverse Assets - Gaming")
    string public name;
    // The token symbol ("BAG")
    string public symbol;

    // mapping (address) to collectionId to amount
    mapping(address => mapping(uint256 => uint256)) public claimedAssets;

    mapping(address => mapping(uint256 => uint256)) public burnedDetails;

    ICancellationRegistry cancellationRegistry;

    address public masterAddress;

    event BurnedAsset(address burner, uint256 tokenId, uint256 amount);

    bytes32 private EIP712_DOMAIN_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 private DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPE_HASH,
                keccak256(bytes("Bullieverse")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );

    /**
     * @dev Initializes the contract by setting the name and the token symbol
     */
    constructor(string memory baseURI) ERC1155(baseURI) {
        name = "Bullieverse LootBox";
        symbol = "BLB";
    }

    /*
     * @dev Sets the registry contracts for the exchange.
     */
    function setRegistryContracts(address _cancellationRegistry)
        external
        onlyOwner
    {
        cancellationRegistry = ICancellationRegistry(_cancellationRegistry);
    }

    /**
     * @dev Change Master Address
     */
    function changeMasterAddresss(address newMasterAddress) external {
        masterAddress = newMasterAddress;
    }

    function _validateSigner(
        uint256 tokenId,
        uint256 amount,
        uint256 blockNumber,
        address redeemer,
        bytes memory signature
    ) public view returns (address) {
        bytes32 MINT = keccak256(
            "ERC1155Voucher(uint256 tokenId,uint256 amount,uint256 blockNumber,address redemeer)"
        );

        bytes32 structHash = keccak256(
            abi.encode(MINT, tokenId, amount, blockNumber, redeemer)
        );

        bytes32 digest = ECDSA.toTypedDataHash(DOMAIN_SEPARATOR, structHash);

        address recoveredAddress = ECDSA.recover(digest, signature);
        return recoveredAddress;
    }

    function _validateBurn(
        uint256 tokenId,
        uint256 amount,
        address bullAddress,
        uint256 bullAmount,
        address burner,
        bytes memory signature
    ) public view returns (address) {
        bytes32 BURN = keccak256(
            "ERC1155Burn(uint256 tokenId,uint256 amount,address bullAddress,uint256 bullAmount,address burner)"
        );

        bytes32 structHash = keccak256(
            abi.encode(BURN, tokenId, amount, bullAddress, bullAmount, burner)
        );

        bytes32 digest = ECDSA.toTypedDataHash(DOMAIN_SEPARATOR, structHash);

        address recoveredAddress = ECDSA.recover(digest, signature);
        return recoveredAddress;
    }

    /**
     * @dev Contracts the metadata URI for the Asset of the given collectionId.
     *
     * Requirements:
     *
     * - The Asset exists for the given collectionId
     */
    function uri(uint256 collectionId)
        public
        view
        override
        returns (string memory)
    {
        return
            string(
                abi.encodePacked(
                    super.uri(collectionId),
                    collectionId.toString(),
                    ".json"
                )
            );
    }

    /**
     * Owner-only methods
     */

    /**
     * @dev Sets the base URI for the Collection metadata.
     */
    function setBaseURI(string memory baseURI) external onlyOwner {
        require(bytes(baseURI).length != 0, "baseURI cannot be empty");
        _setURI(baseURI);
    }

    function mintAsset(
        uint256 collectionId,
        uint256 amount,
        uint256 blockNumber,
        bytes memory signature
    ) external payable {
        require(
            blockNumber >
                cancellationRegistry.getLastTransactionBlockNumber(msg.sender),
            "Invalid Signature"
        );
        address signer = _validateSigner(
            collectionId,
            amount,
            blockNumber,
            msg.sender,
            signature
        );
        require(signer == masterAddress, "Invalid Signer");
        _mint(msg.sender, collectionId, amount, "");
        claimedAssets[msg.sender][collectionId] += amount;
        cancellationRegistry.cancelAllPreviousSignatures(msg.sender);
    }

    function burn(
        uint256 collectionId,
        uint256 amount,
        uint256 bullAmount,
        address tokenAddress,
        bytes memory signature
    ) external payable {
        address signer = _validateBurn(
            collectionId,
            amount,
            tokenAddress,
            bullAmount,
            msg.sender,
            signature
        );
        require(signer == masterAddress, "Invalid Signer");
        if (bullAmount > 0) {
            IERC20(tokenAddress).transferFrom(
                msg.sender,
                masterAddress,
                bullAmount
            );
        }
        _burn(msg.sender, collectionId, amount);
        burnedDetails[msg.sender][collectionId] += amount;
        emit BurnedAsset(msg.sender, collectionId, amount);
    }
}
