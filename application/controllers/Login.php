<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Login extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->load->library('form_validation');
    }

    public function index()
    {
        $this->form_validation->set_rules('username', 'Username', 'required|trim');
        $this->form_validation->set_rules('password', 'Password', 'required|trim');

        if ($this->form_validation->run() == false) {
            $this->load->view('login');
        } else {
            $this->_login();
        }
    }

    private function _login()
    {
        $username = $this->input->post('username');
        $password = $this->input->post('password');

        $user = $this->db->get_where('users', ['username' => $username])->row_array();

        if ($user) {
            // inactive
            if ($user['is_active'] == 1) {
                if (password_verify($password, $user['password'])) {
                    $data = [
                        'id' => $user['id'],
                        'fullname' => $user['fullname'],
                        'username' => $user['username'],
                        'role_id' => $user['role_id'],
                        'member_id' => $user['member_id'],
                        'office_id' => $user['office_id']
                    ];

                    $ipnum = $this->input->ip_address();

                    $uplogin = array(
                        'terminal' => $ipnum,
                        'start_login' => date('Y-m-d H:i:s')
                    );
                    $this->db->set($uplogin);
                    $this->db->where('id', $user['id']);
                    $this->db->update('users');

                    $this->session->set_userdata($data);
                    redirect('webui/main');
                } else {
                    $this->session->set_flashdata('message', '<div class="invalid-feedback">Invalid password!</div>');
                    redirect('login');
                }
            } else {
                $this->session->set_flashdata('message', '<div class="invalid-feedback">Username has not been activated!</div>');
                redirect('login');
            }
        } else {
            $this->session->set_flashdata('message', '<div class="invalid-feedback">Username is not registered!</div>');
            redirect('login');
        }
    }

    public function registration()
    {

        $this->form_validation->set_rules('name', 'Fullname', 'required|trim');
        $this->form_validation->set_rules('username', 'Username', 'required|trim|is_unique[users.username]', [
            'is_unique' => 'Username has already registered!'
        ]);
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[users.email]', [
            'is_unique' => 'Email has already registered!'
        ]);
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[3]|matches[password2]', [
            'matches' => 'Password dont match!',
            'min_length' => 'Password must be at least 3 character!'
        ]);
        $this->form_validation->set_rules('password2', 'Repeat Password', 'required|trim|matches[password1]');

        if ($this->form_validation->run() == false) {
            $data['title'] = 'User Registration';

            $this->load->view('auth/registration');
        } else {
            $data = [
                'username' => htmlspecialchars($this->input->post('username', true)),
                'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
                'email' => htmlspecialchars($this->input->post('email', true)),
                'fullname' => htmlspecialchars($this->input->post('name', true)),
                'phone' => '08123456789',
                'office' => '1',
                'role_id' => '1',
                'image' => 'default.jpg',
                'is_active' => '1',
                'created' => date('Y-m-d H:i:s'),
            ];
            $this->db->insert('users', $data);
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Congratulation! your account has been created. Please login</div>');
            redirect('auth');
        }
    }

    public function logout()
    {
        $id = $this->session->userdata('id');
        $user = $this->db->get_where('users', ['id' => $id])->row_array();


        $uplogin = array(
            'last_login' => $user['start_login'],
            'end_login' => date('Y-m-d H:i:s')
        );
        $this->db->set($uplogin);
        $this->db->where('id', $user['id']);
        $this->db->update('users');

        $this->session->unset_userdata('id');
        $this->session->unset_userdata('fullname');
        $this->session->unset_userdata('username');
        $this->session->unset_userdata('role_id');
        $this->session->unset_userdata('office');

        $this->session->set_flashdata('message', '<div id="warning-success">You have been logged out</div>');
        redirect('auth');
    }
}
