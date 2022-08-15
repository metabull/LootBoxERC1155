// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract LootBox is ERC1155Supply, Ownable {
    using ECDSA for bytes32;
    using Strings for uint256;

    // The name of the token ("Bullieverse Assets - Gaming")
    string public name;
    // The token symbol ("BAG")
    string public symbol;

    // mapping (address) to collectionId to amount
    mapping(address => mapping(uint256 => uint256)) public claimedAssets;

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

    function _validateSigner(
        uint256 tokenId,
        uint256 amount,
        address redeemer,
        bytes memory signature
    ) public view returns (address) {
        bytes32 MINT = keccak256(
            "ERC1155Voucher(uint256 tokenId,uint256 amount,address redemeer)"
        );

        bytes32 structHash = keccak256(
            abi.encode(MINT, tokenId, amount, redeemer)
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
        address redeemer,
        bytes memory signature
    ) public view returns (address) {
        bytes32 MINT = keccak256(
            "ERC1155Burn(uint256 tokenId,uint256 amount, address bullAddress,uint256 bullAmount,address redemeer)"
        );

        bytes32 structHash = keccak256(
            abi.encode(MINT, tokenId, amount, bullAddress, bullAmount, redeemer)
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
        bytes memory signature
    ) external payable {
        address signer = _validateSigner(
            collectionId,
            amount,
            msg.sender,
            signature
        );
        require(signer == owner(), "Invalid Signer");
        uint256 claimAbleAmount = amount -
            claimedAssets[msg.sender][collectionId];
        require(claimAbleAmount != 0, "ERC1155: cannot mint 0 Item");
        _mint(msg.sender, collectionId, claimAbleAmount, "");
        claimedAssets[msg.sender][collectionId] = amount;
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
        require(signer == owner(), "Invalid Signer");
        _burn(msg.sender, collectionId, amount);
        emit BurnedAsset(msg.sender, collectionId, amount);
    }
}
