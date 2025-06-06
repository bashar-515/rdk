package pointcloud

import (
	"github.com/golang/geo/r3"

	"go.viam.com/rdk/spatialmath"
)

// BasicType the type for a basic pointcloud.
const BasicType = "basic"

var basicConfig = TypeConfig{
	StructureType: BasicType,
	NewWithParams: NewBasicPointCloud,
}

func init() {
	Register(basicConfig)
}

// basicPointCloud is the basic implementation of the PointCloud interface backed by
// a map of points keyed by position.
type basicPointCloud struct {
	points storage
	meta   MetaData
}

// NewBasicEmpty creates an empty basic pointcloud.
func NewBasicEmpty() PointCloud {
	return NewBasicPointCloud(0)
}

// NewBasicPointCloud creates a basic cloud with a size.
func NewBasicPointCloud(size int) PointCloud {
	return &basicPointCloud{
		points: &matrixStorage{points: make([]PointAndData, 0, size), indexMap: make(map[r3.Vector]uint, size)},
		meta:   NewMetaData(),
	}
}

func (cloud *basicPointCloud) Size() int {
	return cloud.points.Size()
}

func (cloud *basicPointCloud) MetaData() MetaData {
	return cloud.meta
}

func (cloud *basicPointCloud) At(x, y, z float64) (Data, bool) {
	return cloud.points.At(x, y, z)
}

// Set validates that the point can be precisely stored before setting it in the cloud.
func (cloud *basicPointCloud) Set(p r3.Vector, d Data) error {
	_, pointExists := cloud.At(p.X, p.Y, p.Z)
	if err := cloud.points.Set(p, d); err != nil {
		return err
	}
	if !pointExists {
		cloud.meta.Merge(p, d)
	}
	return nil
}

func (cloud *basicPointCloud) Iterate(numBatches, myBatch int, fn func(p r3.Vector, d Data) bool) {
	cloud.points.Iterate(numBatches, myBatch, fn)
}

func (cloud *basicPointCloud) FinalizeAfterReading() (PointCloud, error) {
	return cloud, nil
}

func (cloud *basicPointCloud) CreateNewRecentered(offset spatialmath.Pose) PointCloud {
	return NewBasicPointCloud(cloud.Size())
}
