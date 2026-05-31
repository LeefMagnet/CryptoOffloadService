// Package client 封装 CryptoOffload gRPC 服务的高层 SDK。
//
// 使用前请先运行项目根目录 `make proto` 生成 `gen/` 代码。
package client

import (
	"context"

	pb "github.com/cryptooffload/sdk-go/gen/cryptooffload/v1"
	"github.com/cryptooffload/sdk-go/pool"
)

// Client 通过连接池访问 Key / Sign / CMS / SCEP 服务。
type Client struct {
	pool *pool.Pool
}

// Config 客户端配置（嵌入连接池配置）。
type Config struct {
	pool.Config
}

// New 创建客户端并预热连接池。
func New(ctx context.Context, cfg Config) (*Client, error) {
	p, err := pool.New(cfg.Config)
	if err != nil {
		return nil, err
	}
	if err := p.Warmup(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	return &Client{pool: p}, nil
}

// Close 关闭底层连接池。
func (c *Client) Close() error {
	return c.pool.Close()
}

func (c *Client) withConn(ctx context.Context, fn func(*pool.Conn) error) error {
	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return fn(conn)
}

// ImportKey 导入密钥，返回 key_id。
func (c *Client) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	var resp *pb.ImportKeyResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewKeyServiceClient(conn.GRPC())
		out, err := cli.ImportKey(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// DeleteKey 删除密钥。
func (c *Client) DeleteKey(ctx context.Context, keyID string) (*pb.DeleteKeyResponse, error) {
	var resp *pb.DeleteKeyResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewKeyServiceClient(conn.GRPC())
		out, err := cli.DeleteKey(ctx, &pb.DeleteKeyRequest{KeyId: keyID})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// GetKeyInfo 查询密钥元数据（不含密钥材料）。
func (c *Client) GetKeyInfo(ctx context.Context, keyID string) (*pb.GetKeyInfoResponse, error) {
	var resp *pb.GetKeyInfoResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewKeyServiceClient(conn.GRPC())
		out, err := cli.GetKeyInfo(ctx, &pb.GetKeyInfoRequest{KeyId: keyID})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// ListKeys 列出所有密钥元数据。
func (c *Client) ListKeys(ctx context.Context) (*pb.ListKeysResponse, error) {
	var resp *pb.ListKeysResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewKeyServiceClient(conn.GRPC())
		out, err := cli.ListKeys(ctx, &pb.ListKeysRequest{})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// Sign 使用 key_id 对 data 做摘要并签名。
func (c *Client) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	var resp *pb.SignResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewSignServiceClient(conn.GRPC())
		out, err := cli.Sign(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// Verify 使用 key_id 验签。
func (c *Client) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	var resp *pb.VerifyResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewSignServiceClient(conn.GRPC())
		out, err := cli.Verify(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// ParseCMS 解析 CMS/PKCS#7。
func (c *Client) ParseCMS(ctx context.Context, req *pb.ParseCmsRequest) (*pb.ParseCmsResponse, error) {
	var resp *pb.ParseCmsResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewCmsServiceClient(conn.GRPC())
		out, err := cli.Parse(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// BuildCMS 构建 CMS SignedData。
func (c *Client) BuildCMS(ctx context.Context, req *pb.BuildCmsRequest) (*pb.BuildCmsResponse, error) {
	var resp *pb.BuildCmsResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewCmsServiceClient(conn.GRPC())
		out, err := cli.Build(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// VerifyCMS 验证 CMS SignedData。
func (c *Client) VerifyCMS(ctx context.Context, req *pb.VerifyCmsRequest) (*pb.VerifyCmsResponse, error) {
	var resp *pb.VerifyCmsResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewCmsServiceClient(conn.GRPC())
		out, err := cli.Verify(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// ParseScepRequest 解析 SCEP PKIO 请求。
func (c *Client) ParseScepRequest(ctx context.Context, req *pb.ParseScepRequestRequest) (*pb.ParseScepRequestResponse, error) {
	var resp *pb.ParseScepRequestResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepServiceClient(conn.GRPC())
		out, err := cli.ParseRequest(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// BuildScepSuccessCertRep 构建 SCEP SUCCESS CertRep。
func (c *Client) BuildScepSuccessCertRep(ctx context.Context, req *pb.BuildScepSuccessCertRepRequest) (*pb.BuildScepCertRepResponse, error) {
	var resp *pb.BuildScepCertRepResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepServiceClient(conn.GRPC())
		out, err := cli.BuildSuccessCertRep(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// BuildScepFailureCertRep 构建 SCEP FAILURE CertRep。
func (c *Client) BuildScepFailureCertRep(ctx context.Context, req *pb.BuildScepFailureCertRepRequest) (*pb.BuildScepCertRepResponse, error) {
	var resp *pb.BuildScepCertRepResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepServiceClient(conn.GRPC())
		out, err := cli.BuildFailureCertRep(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// BuildScepPendingCertRep 构建 SCEP PENDING CertRep（pkiStatus=3）。
func (c *Client) BuildScepPendingCertRep(ctx context.Context, req *pb.BuildScepPendingCertRepRequest) (*pb.BuildScepCertRepResponse, error) {
	var resp *pb.BuildScepCertRepResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepServiceClient(conn.GRPC())
		out, err := cli.BuildPendingCertRep(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// ParseScepSignedAttributes 解析 PKCS#7 SCEP SignedAttributes。
func (c *Client) ParseScepSignedAttributes(ctx context.Context, req *pb.ParseScepSignedAttributesRequest) (*pb.ParseScepSignedAttributesResponse, error) {
	var resp *pb.ParseScepSignedAttributesResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepExtServiceClient(conn.GRPC())
		out, err := cli.ParseSignedAttributes(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// ParseGetCertPkio 解析 GetCert PKIO（CertAliasOrCn 内层）。
func (c *Client) ParseGetCertPkio(ctx context.Context, req *pb.ParseGetCertPkioRequest) (*pb.ParseGetCertPkioResponse, error) {
	var resp *pb.ParseGetCertPkioResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepExtServiceClient(conn.GRPC())
		out, err := cli.ParseGetCertPkio(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// EncodeCertAliasContent 编码 CertAliasOrCn / SerialNumber DER。
func (c *Client) EncodeCertAliasContent(ctx context.Context, req *pb.EncodeCertAliasContentRequest) (*pb.EncodeCertAliasContentResponse, error) {
	var resp *pb.EncodeCertAliasContentResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepExtServiceClient(conn.GRPC())
		out, err := cli.EncodeCertAliasContent(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}

// EncodeScepHttpQuery 构建 SCEP HTTP query。
func (c *Client) EncodeScepHttpQuery(ctx context.Context, req *pb.EncodeScepHttpQueryRequest) (*pb.EncodeScepHttpQueryResponse, error) {
	var resp *pb.EncodeScepHttpQueryResponse
	err := c.withConn(ctx, func(conn *pool.Conn) error {
		cli := pb.NewScepExtServiceClient(conn.GRPC())
		out, err := cli.EncodeScepHttpQuery(ctx, req)
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	return resp, err
}
