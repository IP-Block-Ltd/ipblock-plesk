<?php
/**
 * IP-Block.com — Plesk settings controller.
 *
 * Renders and processes the extension's settings page inside the Plesk UI.
 * On save it delegates to Modules_Ipblock_Config, which writes the JSON config
 * file consumed by the shared enforcement guard.
 */
class IndexController extends pm_Controller_Action
{
    public function init()
    {
        parent::init();
        $this->view->pageTitle = 'IP-Block Protection';

        // Left-nav tab.
        $this->view->tabs = array(
            array(
                'title'  => 'Settings',
                'action' => 'index',
            ),
        );
    }

    public function indexAction()
    {
        $cfg  = Modules_Ipblock_Config::load();
        $form = new pm_Form_Simple();

        $form->addElement('checkbox', 'enabled', array(
            'label' => 'Enable protection (server-wide)',
            'value' => $cfg['enabled'],
        ));

        $form->addElement('text', 'site_id', array(
            'label'      => 'Site ID',
            'value'      => $cfg['site_id'],
            'class'      => 'f-large-size',
            'autocomplete' => 'off',
        ));

        $form->addElement('text', 'api_key', array(
            'label'      => 'API Key',
            'value'      => $cfg['api_key'],
            'class'      => 'f-large-size',
            'autocomplete' => 'off',
        ));

        $form->addElement('text', 'api_url', array(
            'label' => 'API URL',
            'value' => $cfg['api_url'],
            'class' => 'f-large-size',
            'description' => 'Default: https://api.ip-block.com/v1/check',
        ));

        $form->addElement('checkbox', 'fail_open', array(
            'label' => 'Fail open (allow visitors when the API is unreachable)',
            'value' => $cfg['fail_open'],
        ));

        $form->addElement('text', 'cache_ttl', array(
            'label'    => 'Cache TTL (seconds)',
            'value'    => $cfg['cache_ttl'],
            'validators' => array(array('Int', true), array('GreaterThan', true, array('min' => -1))),
        ));

        $form->addElement('checkbox', 'behind_proxy', array(
            'label' => 'Server is behind a proxy / CDN (trust real-IP header)',
            'value' => $cfg['behind_proxy'],
        ));

        $form->addElement('text', 'real_ip_header', array(
            'label' => 'Real-IP header',
            'value' => $cfg['real_ip_header'],
            'description' => 'Used only when "behind proxy" is enabled. e.g. X-Forwarded-For, CF-Connecting-IP',
        ));

        $form->addElement('select', 'block_action', array(
            'label'        => 'Block action',
            'multiOptions' => array('403' => 'Return HTTP 403', 'redirect' => 'Redirect'),
            'value'        => $cfg['block_action'],
        ));

        $form->addElement('text', 'block_message', array(
            'label' => 'Block message (403 mode)',
            'value' => $cfg['block_message'],
            'class' => 'f-large-size',
        ));

        $form->addElement('text', 'redirect_url', array(
            'label' => 'Redirect URL (redirect mode)',
            'value' => $cfg['redirect_url'],
            'class' => 'f-large-size',
        ));

        $form->addElement('textarea', 'whitelist', array(
            'label'       => 'Whitelist (one IP or CIDR per line)',
            'value'       => implode("\n", $cfg['whitelist']),
            'rows'        => 5,
            'cols'        => 60,
            'description' => 'Never sent to the API and always allowed. IPv4/IPv6, CIDR supported.',
        ));

        $form->addControlButtons(array(
            'cancelLink' => pm_Context::getModulesListUrl(),
        ));

        if ($this->getRequest()->isPost() && $form->isValid($this->getRequest()->getPost())) {
            $values = $form->getValues();

            if (!empty($values['enabled']) &&
                (trim($values['site_id']) === '' || trim($values['api_key']) === '')) {
                $this->_status->addMessage('error', 'Site ID and API Key are required to enable protection.');
            } else {
                Modules_Ipblock_Config::save($values);
                $this->_status->addMessage('info', 'Settings saved.');
                $this->_helper->json(array('redirect' => pm_Context::getBaseUrl()));
                return;
            }
        }

        $this->view->form = $form;
    }
}
