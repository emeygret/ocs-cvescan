<?php
function extension_install_cvescan()
{
    $object = new ExtensionCommon;
    $object -> sqlQuery("CREATE TABLE IF NOT EXISTS `cvescan` (
     `ID` INT(11) NOT NULL AUTO_INCREMENT,
     `HARDWARE_ID` INT(11) NOT NULL,
     `CVE_ID` VARCHAR(255) DEFAULT NULL,
     `CVE_PRIORITY` VARCHAR(255) DEFAULT NULL,
     `CVE_PACKAGE` VARCHAR(255) DEFAULT NULL,
     `CVE_FIXED_VERSION` VARCHAR(255) DEFAULT NULL,
     `CVE_REPOSITORY` VARCHAR(255) DEFAULT NULL,
     PRIMARY KEY  (`ID`,`HARDWARE_ID`)
     ) ENGINE=InnoDB ;");
}

function extension_delete_cvescan()
{
    $object = new ExtensionCommon;
    $object -> sqlQuery("DROP TABLE `cvescan`;");
}

function extension_upgrade_cvescan()
{

}
?>
