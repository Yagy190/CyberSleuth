// CyberSleuth AI – App Shell Layout (sidebar + header)
// Member 3: Frontend & Security Visualization
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu, Button, Typography, Space, Tag } from 'antd'
import {
  DashboardOutlined, AlertOutlined, FileSearchOutlined,
  LogoutOutlined, SafetyCertificateOutlined
} from '@ant-design/icons'
import { useAuth } from '../hooks/useAuth'

const { Header, Sider, Content } = Layout
const { Title, Text } = Typography

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate  = useNavigate()
  const location  = useLocation()

  const selectedKey = location.pathname === '/' ? '/'
    : location.pathname.startsWith('/incidents') ? '/incidents'
    : '/'

  const menuItems = [
    { key: '/',          icon: <DashboardOutlined />,    label: 'Dashboard'  },
    { key: '/incidents', icon: <FileSearchOutlined />,   label: 'Incidents'  },
    { key: '/alerts',    icon: <AlertOutlined />,        label: 'Alerts'     },
  ]

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        width={220}
        style={{ background: '#161b22', borderRight: '1px solid #30363d' }}
      >
        {/* Logo */}
        <div style={{ padding: '20px 16px 12px', borderBottom: '1px solid #30363d' }}>
          <Space>
            <SafetyCertificateOutlined style={{ fontSize: 22, color: '#1677ff' }} />
            <Title level={5} style={{ color: '#e6edf3', margin: 0 }}>
              CyberSleuth AI
            </Title>
          </Space>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          onClick={({ key }) => navigate(key)}
          items={menuItems}
          style={{ background: '#161b22', borderRight: 'none', marginTop: 8 }}
        />
      </Sider>

      <Layout>
        <Header
          style={{
            background: '#161b22',
            borderBottom: '1px solid #30363d',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 24px',
          }}
        >
          <Text style={{ color: '#8b949e', fontSize: 13 }}>
            Autonomous Security Investigation Platform
          </Text>
          <Space>
            {user?.is_admin && <Tag color="gold">Admin</Tag>}
            <Text style={{ color: '#c9d1d9' }}>{user?.username}</Text>
            <Button
              type="text"
              icon={<LogoutOutlined />}
              onClick={logout}
              style={{ color: '#8b949e' }}
            >
              Logout
            </Button>
          </Space>
        </Header>

        <Content style={{ padding: 24, background: '#0d1117' }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
